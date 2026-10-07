/* Copyright 2026 The Forbric Project. Licensed under the Apache License, Version 2.0. */
package net.forbric.kernel.transform;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import net.fabricmc.api.EnvType;

/**
 * {@link CommonNetworkInteropInjector}'s output, run against the kernel's real boot-side {@code PayloadInterop}: its
 * repairs, each on stand-ins for the class it edits, each with the merged failure it prevents.
 * <ul>
 *   <li>fabric-api's channel addon handed NeoForge's {@code c:version} payload: the negotiation runs for both stacks
 *       and the addon never reaches its cast — as merged, {@code ClassCastException} and "invalid packet";</li>
 *   <li>the server finishing Fabric's {@code c:version} task while NeoForge's equivalent is current: the next task
 *       starts — as merged, "Unexpected request for task finish";</li>
 *   <li>NeoForge's {@code checkPacket}: a payload another ecosystem negotiated is not policed, and a
 *       NeoForge-registered or vanilla one still is;</li>
 *   <li>and, unclaimed, the client's register answered by fabric-api before NeoForge.</li>
 * </ul>
 * Not run here: the HEDGE initialisation guard (inert since NeoForge 26.2.0.88). The injector has no switch of its
 * own: {@code -Dforbric.commonNetworkInterop=off} is read where KernelBoot registers it.
 */
@ExecutesInjector(CommonNetworkInteropInjector.class)
class CommonNetworkInteropInjectorExecutionTest {
	private static final String ADDON = "net.fabricmc.fabric.impl.networking.AbstractChanneledNetworkAddon";
	private static final String SERVER_CONFIG = "net.minecraft.server.network.ServerConfigurationPacketListenerImpl";
	private static final String CLIENT_COMMON = "net.minecraft.client.multiplayer.ClientCommonPacketListenerImpl";
	private static final String CLIENT_CONFIG = "net.minecraft.client.multiplayer.ClientConfigurationPacketListenerImpl";
	private static final String NEO_REGISTRY = "net.neoforged.neoforge.network.registration.NetworkRegistry";
	private static final List<String> TARGETS = List.of(ADDON, SERVER_CONFIG, CLIENT_CONFIG, NEO_REGISTRY);

	private static String payload(String binaryName, String fields, String id) {
		int dot = binaryName.lastIndexOf('.');
		return """
				package %s;

				import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
				import net.minecraft.resources.Identifier;

				public record %s(%s) implements CustomPacketPayload {
					public Type type() {
						return new Type(%s);
					}
				}
				""".formatted(binaryName.substring(0, dot), binaryName.substring(dot + 1), fields, id);
	}

	private static String customPacket(String name) {
		return """
				package net.minecraft.network.protocol.common;

				import net.minecraft.network.protocol.Packet;
				import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

				public record %s(CustomPacketPayload payload) implements Packet {
				}
				""".formatted(name);
	}

	/** A common listener: fabric-api's head injection answers minecraft:register, then NeoForge's body. */
	private static String commonListener(String pkg, String name, String packet) {
		return """
				package %s;

				import java.util.ArrayList;
				import java.util.List;
				import net.minecraft.network.Connection;
				import net.minecraft.network.protocol.common.%s;
				import net.neoforged.neoforge.network.registration.NetworkRegistry;

				public class %s {
					protected final Connection connection;
					public final List<String> handled = new ArrayList<>();

					public %s(Connection connection) {
						this.connection = connection;
					}

					public void handleCustomPayload(%s packet) {
						String id = packet.payload().type().id().toString();
						if (id.equals("minecraft:register")) {
							handled.add("fabric");
							return;
						}
						if (NetworkRegistry.registered(id)) handled.add("neoforge " + id);
						else connection.disconnect("No Channel for " + id);
					}
				}
				""".formatted(pkg, packet, name, name, packet);
	}

	private static final Map<String, String> STAND_INS = new HashMap<>(Map.of(
			"net.minecraft.resources.Identifier", """
					package net.minecraft.resources;

					public record Identifier(String id) {
						@Override
						public String toString() {
							return id;
						}
					}
					""",
			"net.minecraft.network.protocol.common.custom.CustomPacketPayload", """
					package net.minecraft.network.protocol.common.custom;

					import net.minecraft.resources.Identifier;

					public interface CustomPacketPayload {
						record Type(Identifier id) {
						}

						Type type();
					}
					""",
			"net.minecraft.network.Connection", """
					package net.minecraft.network;

					public class Connection {
						public String disconnected;

						public void disconnect(String reason) {
							disconnected = reason;
						}
					}
					""",
			"net.minecraft.network.protocol.Packet", "package net.minecraft.network.protocol; public interface Packet { }",
			"net.minecraft.network.protocol.common.ClientboundCustomPayloadPacket", customPacket("ClientboundCustomPayloadPacket"),
			"net.minecraft.network.protocol.common.ServerboundCustomPayloadPacket", customPacket("ServerboundCustomPayloadPacket"),
			"fixture.ModPayload", payload("fixture.ModPayload", "String id", "new Identifier(id)"),
			"net.neoforged.neoforge.network.payload.CommonVersionPayload",
			payload("net.neoforged.neoforge.network.payload.CommonVersionPayload", "java.util.List<Integer> versions",
					"new Identifier(\"c:version\")"),
			"net.fabricmc.fabric.impl.networking.CommonVersionPayload",
			payload("net.fabricmc.fabric.impl.networking.CommonVersionPayload", "int[] versions", "new Identifier(\"c:version\")")));

	static {
		STAND_INS.put("net.neoforged.neoforge.network.payload.MinecraftRegisterPayload",
				payload("net.neoforged.neoforge.network.payload.MinecraftRegisterPayload", "java.util.Set<Identifier> channels",
						"new Identifier(\"minecraft:register\")"));
		STAND_INS.put("net.minecraft.network.protocol.common.ServerCommonPacketListener", """
				package net.minecraft.network.protocol.common;

				public interface ServerCommonPacketListener {
					boolean negotiated(String channel);
				}
				""");
		STAND_INS.put(NEO_REGISTRY, """
				package net.neoforged.neoforge.network.registration;

				import java.util.ArrayList;
				import java.util.List;
				import java.util.Map;
				import net.minecraft.network.protocol.Packet;
				import net.minecraft.network.protocol.common.ServerCommonPacketListener;
				import net.minecraft.network.protocol.common.ServerboundCustomPayloadPacket;
				import net.minecraft.resources.Identifier;
				import net.neoforged.neoforge.network.payload.CommonVersionPayload;

				public class NetworkRegistry {
					public static final Map<String, Map<Identifier, String>> PAYLOAD_REGISTRATIONS =
							Map.of("play", Map.of(new Identifier("neomod:sync"), "registered"));
					public static final List<Object> commonVersions = new ArrayList<>();

					public static boolean registered(String id) {
						return PAYLOAD_REGISTRATIONS.get("play").containsKey(new Identifier(id));
					}

					public static void checkCommonVersion(Object listener, CommonVersionPayload payload) {
						commonVersions.add(payload.versions());
					}

					/** NeoForge's channel police: what this connection did not negotiate may not be sent. */
					public static void checkPacket(Packet packet, ServerCommonPacketListener listener) {
						if (packet instanceof ServerboundCustomPayloadPacket custom) {
							String id = custom.payload().type().id().toString();
							if (!listener.negotiated(id)) throw new UnsupportedOperationException("Payload " + id + " may not be sent to the server!");
						}
					}
				}
				""");
		STAND_INS.put("net.neoforged.neoforge.network.registration.ClientNetworkRegistry", """
				package net.neoforged.neoforge.network.registration;

				import net.minecraft.client.multiplayer.ClientCommonPacketListenerImpl;

				public class ClientNetworkRegistry {
					public static void sendInitialListeningChannels(ClientCommonPacketListenerImpl listener) {
						listener.handled.add("neoforge");
					}
				}
				""");
		STAND_INS.put(ADDON, """
				package net.fabricmc.fabric.impl.networking;

				import net.minecraft.network.protocol.common.custom.CustomPacketPayload;

				public abstract class AbstractChanneledNetworkAddon {
					protected final Object listener;
					public int negotiatedVersion = -1;

					protected AbstractChanneledNetworkAddon(Object listener) {
						this.listener = listener;
					}

					/** fabric-api's: a payload under a common-networking id is taken to be its own type. */
					public boolean handle(CustomPacketPayload payload) {
						if (payload.type().id().toString().equals("c:version")) {
							onCommonVersionPacket(((CommonVersionPayload) payload).versions()[0]);
							return true;
						}
						return false;
					}

					protected void onCommonVersionPacket(int version) {
						negotiatedVersion = version;
					}
				}
				""");
		STAND_INS.put("fixture.PlayAddon", """
				package fixture;

				public class PlayAddon extends net.fabricmc.fabric.impl.networking.AbstractChanneledNetworkAddon {
					public PlayAddon(Object listener) {
						super(listener);
					}
				}
				""");
		STAND_INS.put("net.minecraft.server.network.ConfigurationTask", """
				package net.minecraft.server.network;

				import java.util.function.Consumer;

				public interface ConfigurationTask {
					record Type(String id) {
					}

					Type type();

					void start(Consumer<String> send);
				}
				""");
		STAND_INS.put(SERVER_CONFIG, """
				package net.minecraft.server.network;

				import java.util.ArrayDeque;
				import java.util.ArrayList;
				import java.util.List;
				import java.util.Queue;

				public class ServerConfigurationPacketListenerImpl {
					public final Queue<ConfigurationTask> tasks = new ArrayDeque<>();
					public final List<String> sent = new ArrayList<>();
					private ConfigurationTask currentTask;

					public void startConfiguration() {
						startNextTask();
					}

					public String current() {
						return currentTask == null ? null : currentTask.type().id();
					}

					/** Vanilla's. */
					public void finishCurrentTask(ConfigurationTask.Type type) {
						ConfigurationTask.Type current = currentTask != null ? currentTask.type() : null;
						if (!type.equals(current)) {
							throw new IllegalStateException("Unexpected request for task finish, current task: " + current + ", requested: " + type);
						}
						currentTask = null;
						startNextTask();
					}

					/** NeoForge's body: the vanilla start overload. */
					private void startNextTask() {
						if (currentTask != null) throw new IllegalStateException("Task " + currentTask.type().id() + " has not finished yet");
						ConfigurationTask task = tasks.poll();
						if (task != null) {
							currentTask = task;
							task.start(this::send);
						}
					}

					void send(String packet) {
						sent.add(packet);
					}
				}
				""");
		STAND_INS.put("fixture.Tasks", """
				package fixture;

