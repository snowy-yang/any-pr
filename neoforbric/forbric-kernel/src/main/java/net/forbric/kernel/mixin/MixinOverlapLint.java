/*
 * Copyright 2026 The Forbric Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.forbric.kernel.mixin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.electronwill.nightconfig.core.UnmodifiableConfig;
import com.electronwill.nightconfig.json.JsonFormat;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import net.forbric.api.CompatibilityFinding;
import net.forbric.api.CompatibilityFindings;
import net.forbric.kernel.util.ForbricLog;

/**
 * Two mods' mixins that claim the same method in ways that cannot both take effect.
 *
 * <p>{@link MixinFit} asks whether ONE mixin still fits the merged base. A mixed pack fails a second way that no
 * single-mixin judgement can see: each mod fits, and the two of them together do not. When two mods {@code @Overwrite}
 * the same method only one body survives: a higher-priority overwrite replaces a lower one without a word, and at
 * equal priority the second is skipped with one WARN line ({@code MixinApplicatorStandard.mergeMethod}). When two
 * {@code @Redirect} the same call Mixin keeps one of them. And every overwrite is merged before any injector is
 * applied, so another mod's injector always lands in the overwrite's body, not the one it was written against. Which
 * mod "wins" depends on priorities neither author chose with the other in mind.
 *
 * <p>The rules, each between claims of DIFFERENT mods on one target method:
 * <ul>
 *   <li>{@link Rule#R1} two {@code @Overwrite}s of the method;
 *   <li>{@link Rule#R2} two {@code @Redirect}s of the same call, with equal or unspecified ordinals;
 *   <li>{@link Rule#R3} an {@code @Overwrite} and any injector of another mod in the method;
 *   <li>{@link Rule#R4} (a note) a {@code @Redirect} and another mod's {@code @WrapOperation} or
 *       {@code @ModifyExpressionValue} on the same call. MixinExtras is built to compose with a redirect, so this is
 *       where to look, not a conflict.
 * </ul>
 *
 * <p>Like {@link MixinFit} it is conservative in the direction that cannot accuse: a selector it cannot pin to one
 * method (a wildcard, a regex, a bare name it cannot resolve) contributes no claim, and slices are not read, so two
 * redirects confined to different slices of one method still read as the same call.
 *
 * <p>Runtime ({@link #reportRegistered}): one {@link CompatibilityFinding.Confidence#SUSPECTED} finding per mod and
 * conflict, and {@link #conflictsIn} for {@code CrashAttribution}. {@code -Dforbric.mixinOverlapLint=off} skips both.
 * Offline: {@code MixinOverlapLint <merged-base.jar> <mods-dir> [--json out]}.
 */
public final class MixinOverlapLint {
	public static final String SWITCH = "forbric.mixinOverlapLint";

	private static final String OVERWRITE_DESC = "Lorg/spongepowered/asm/mixin/Overwrite;";
	private static final String REDIRECT = "Redirect";
	private static final String OVERWRITE = "Overwrite";
	/** The MixinExtras injectors that wrap a call another mod may have redirected. */
	private static final Set<String> CALL_WRAPPERS = Set.of("WrapOperation", "ModifyExpressionValue");
	/** {@code @At} values whose target names one call or field access inside the method. */
	private static final Set<String> CALL_POINTS = Set.of("INVOKE", "INVOKE_ASSIGN", "FIELD", "NEW");

	public enum Rule {
		R1(true, "two @Overwrite of one method"),
		R2(true, "two @Redirect of one call"),
		R3(true, "@Overwrite and another mod's injector in one method"),
		R4(false, "@Redirect and another mod's @WrapOperation/@ModifyExpressionValue of one call");

		/** False for a note: worth showing beside a crash or in the offline table, not a finding. */
		public final boolean conflict;
		public final String summary;

		Rule(boolean conflict, String summary) {
			this.conflict = conflict;
			this.summary = summary;
		}
	}

	/**
	 * One handler's claim on one target method.
	 *
	 * @param kind     the annotation's simple name: {@code Overwrite}, {@code Redirect}, {@code Inject}, …
	 * @param owner    the target class, internal name
	 * @param atValue  the {@code @At} value ({@code INVOKE}, {@code HEAD}, …), or null for an overwrite or a point-less
	 *                 injector such as {@code @WrapMethod}
	 * @param atTarget the {@code @At} target in one spelling ({@code Lowner;name(desc)}), or null
	 * @param ordinal  the {@code @At} ordinal, {@code -1} when unspecified
	 * @param array    the config array the mixin is listed in: {@code mixins}, {@code client} or {@code server}
	 * @param family   the mod as a player installed it: the jar's own mod for one it carries inside itself. Claims of
	 *                 one family never overlap -- C2ME's modules overwrite and inject into one method by design, and
	 *                 two of the first sweep's eleven R3 rows were exactly that
	 */
	public record Claim(String modId, String config, String mixin, String handler, String kind, String owner,
			String method, String desc, String atValue, String atTarget, int ordinal, String array, String family) {
		String methodKey() {
			return owner + "." + method + desc;
		}

		boolean overwrite() {
			return OVERWRITE.equals(kind);
		}

		/** {@code config:Mixin.handler}, as a log line names it. */
		public String site() {
			return config + ":" + mixin.substring(mixin.lastIndexOf('.') + 1) + "." + handler;
		}
	}

	/**
	 * Two claims of different mods that collide.
	 *
	 * @param first the overwrite for R3, the redirect for R4, otherwise the claim of the mod id that sorts first
	 */
	public record Overlap(Rule rule, Claim first, Claim second) {
		public String owner() {
			return first.owner();
		}

		public String method() {
			return first.method();
		}

		public String desc() {
			return first.desc();
		}

		/** The call both claim, for R2 and R4; null when the whole method is the point. */
		public String at() {
			return rule == Rule.R2 || rule == Rule.R4 ? first.atTarget() : null;
		}

		/** {@code mixin-overlap:<owner>.<name><desc>[@<at>]}: stable, with no prose in it. */
		public String id() {
			return "mixin-overlap:" + owner().replace('/', '.') + "." + method() + desc() + (at() == null ? "" : "@" + at());
		}

		/** {@code Minecraft.tick}, for prose. */
		public String where() {
			return owner().substring(owner().lastIndexOf('/') + 1) + "." + method();
		}
	}

	private static volatile List<Overlap> recorded = List.of();

	private MixinOverlapLint() {
	}

	static boolean enabled() {
		return !"off".equalsIgnoreCase(System.getProperty(SWITCH, "on"));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Claims
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * Every method {@code mixinBytes} overwrites or injects into, per handler and per {@code @At}.
	 *
	 * @param resolver maps {@code some/pkg/Name.class} to the target's bytes, as {@link MixinFit#evaluate} takes it;
	 *                 a bare-name selector on a target it cannot see contributes nothing
	 */
	public static List<Claim> claims(String modId, String config, byte[] mixinBytes, Function<String, byte[]> resolver) {
		return claims(modId, modId, config, "mixins", mixinBytes, resolver);
	}

	static List<Claim> claims(String modId, String family, String config, String array, byte[] mixinBytes,
			Function<String, byte[]> resolver) {
		ClassNode mixin = new ClassNode();
		new ClassReader(mixinBytes).accept(mixin, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
		List<String> targets = MixinFit.mixinTargets(mixin);
		if (targets.isEmpty() || mixin.methods == null) return List.of();
		String mixinName = mixin.name.replace('/', '.');

		List<Claim> out = new ArrayList<>();
		for (String target : targets) {
			ClassNode targetNode = null;
			boolean read = false;
			for (MethodNode m : mixin.methods) {
				if (m.name.startsWith("<")) continue;
				if (annotated(m, OVERWRITE_DESC)) {
					out.add(new Claim(modId, config, mixinName, m.name, OVERWRITE, target, m.name, m.desc, null, null, -1,
							array, family));
					continue;
				}
				AnnotationNode injector = MixinFit.injectorOf(m);
				if (injector == null) continue;
				if (!read) {
					targetNode = readTarget(target, resolver);
					read = true;
				}
				String kind = injector.desc.substring(injector.desc.lastIndexOf('/') + 1, injector.desc.length() - 1);
				List<AnnotationNode> ats = MixinFit.atNodes(injector);
				for (String[] bound : bound(injector, targetNode, resolver)) {
					if (ats.isEmpty()) {
						out.add(new Claim(modId, config, mixinName, m.name, kind, target, bound[0], bound[1], null, null, -1,
								array, family));
						continue;
					}
					for (AnnotationNode at : ats) {
						String value = MixinFit.asString(MixinFit.value(at, "value"));
						String point = MixinFit.asString(MixinFit.value(at, "target"));
						int ordinal = MixinFit.value(at, "ordinal") instanceof Integer i ? i : -1;
						out.add(new Claim(modId, config, mixinName, m.name, kind, target, bound[0], bound[1], value,
								point == null ? null : canonical(point), ordinal, array, family));
					}
				}
			}
		}
		return out;
	}

	/**
	 * The {@code {name, desc}} pairs an injector binds on {@code target}: the methods {@link MixinFit#resolveSelector}
	 * finds that the target itself declares (Mixin injects into nothing it inherits). A selector with a full
	 * descriptor still names its method when the target cannot be read.
	 */
	private static List<String[]> bound(AnnotationNode injector, ClassNode target, Function<String, byte[]> resolver) {
		List<String[]> out = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		for (String selector : MixinFit.stringList(MixinFit.value(injector, "method"))) {
			if (!MixinFit.exactSelector(selector)) continue;
			if (target == null) {
				String s = selector.replaceAll("\\s+", "");
				int semi = s.indexOf(';');
				if (s.startsWith("L") && semi > 0) s = s.substring(semi + 1);
				int paren = s.indexOf('(');
				if (paren > 0 && seen.add(s)) out.add(new String[] { s.substring(0, paren), s.substring(paren) });
				continue;
			}
			for (MethodNode hit : MixinFit.resolveSelector(target, selector, resolver)) {
				if (target.methods == null || !target.methods.contains(hit)) continue;
				if (seen.add(hit.name + hit.desc)) out.add(new String[] { hit.name, hit.desc });
			}
		}
		return out;
	}

	private static ClassNode readTarget(String target, Function<String, byte[]> resolver) {
		byte[] bytes = resolver == null ? null : resolver.apply(target + ".class");
		if (bytes == null) return null;
		try {
			ClassNode node = new ClassNode();
			new ClassReader(bytes).accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
			return node;
		} catch (RuntimeException unreadable) {
			return null;
		}
	}

	/**
	 * One spelling for a member target: Mixin takes {@code Lowner;name(desc)} and {@code owner.name(desc)} alike, and
	 * two mods naming one call in different spellings still name one call.
	 */
	static String canonical(String point) {
		MixinFit.Member m = MixinFit.parseMember(point);
		if (m == null) return point.replaceAll("\\s+", "");
		String desc = m.desc() == null ? "" : m.desc().startsWith("(") ? m.desc() : ":" + m.desc();
		return (m.owner() == null ? "" : "L" + m.owner() + ";") + m.name() + desc;
	}

	private static boolean annotated(MethodNode m, String desc) {
		for (List<AnnotationNode> table : java.util.Arrays.asList(m.visibleAnnotations, m.invisibleAnnotations)) {
			if (table == null) continue;
			for (AnnotationNode a : table) if (desc.equals(a.desc)) return true;
		}
		return false;
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Overlaps
	// ---------------------------------------------------------------------------------------------------------------

	/** Every collision between claims of different mod families, one per rule, method, call and pair of mods. */
