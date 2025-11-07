package org.opensearch.common.settings;

import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodeRole;

import javax.net.ssl.SNIHostName;
import java.util.List;
import java.util.stream.Collectors;

public class Node {
    public static final Setting<String> NODE_NAME_SETTING = Setting.simpleString("node.name", Setting.Property.NodeScope);
    public static final Setting<Boolean> NODE_LOCAL_STORAGE_SETTING = Setting.boolSetting(
            "node.local_storage",
            true,
            Setting.Property.Deprecated,
            Setting.Property.NodeScope
    );
    public static final Setting.AffixSetting<String> NODE_ATTRIBUTES = Setting.prefixKeySetting(
            "node.attr.",
            (key) -> new Setting<>(key, "", (value) -> {
                if (value.length() > 0
                        && (Character.isWhitespace(value.charAt(0)) || Character.isWhitespace(value.charAt(value.length() - 1)))) {
                    throw new IllegalArgumentException(key + " cannot have leading or trailing whitespace " + "[" + value + "]");
                }
                if (value.length() > 0 && "node.attr.server_name".equals(key)) {
                    try {
                        new SNIHostName(value);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("invalid node.attr.server_name [" + value + "]", e);
                    }
                }
                return value;
            }, Setting.Property.NodeScope)
    );

    public static final Setting<List<DiscoveryNodeRole>> NODE_ROLES_SETTING = Setting.listSetting(
            "node.roles",
            null,
            DiscoveryNode::getRoleFromRoleName,
            settings -> DiscoveryNode.getPossibleRoles()
                    .stream()
                    .filter(role -> role.isEnabledByDefault(settings))
                    .map(DiscoveryNodeRole::roleName)
                    .collect(Collectors.toList()),
            roles -> {
                for (DiscoveryNodeRole role : roles) {
                    role.validateRole(roles);
                }
            },
            Setting.Property.NodeScope
    );
}
