# Reference vocabulary only: never permission evidence or a suitability ranking.
class PortServiceDescriptions
  SOURCE_URL = "https://github.com/fedora-selinux/selinux-policy/blob/5cac04d24778cfec5f6aee261aac01be0f9e1de4/policy/modules/kernel/corenetwork.te.in".freeze
  MACRO_URL = "https://github.com/fedora-selinux/selinux-policy/blob/5cac04d24778cfec5f6aee261aac01be0f9e1de4/policy/modules/kernel/corenetwork.te.m4".freeze
  SERVICES = {
    "http_port_t" => ["http", "HTTP service"],
    "http_cache_port_t" => ["http_cache", "HTTP cache service"],
    "jboss_management_port_t" => ["jboss_management", "JBoss management"],
    "jboss_messaging_port_t" => ["jboss_messaging", "JBoss messaging"],
    "jboss_debug_port_t" => ["jboss_debug", "JBoss debugging"],
    "puppet_port_t" => ["puppet", "Puppet service"]
  }.freeze

  def self.for(type)
    id, label = SERVICES[type]
    return unless id

    { id: id, label: label, description: "Reference policy declares this classification for #{label}. Confirm that the intended listener or destination really serves this role.",
      source: "Fedora SELinux reference policy", source_url: SOURCE_URL, macro_url: MACRO_URL,
      source_entry: "network_port(#{id}, ...) declares #{type}" }
  end
end
