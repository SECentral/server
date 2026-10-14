const OS_NAMES: Record<string, string> = {
  rhel: "RHEL",
  almalinux: "AlmaLinux",
  centos: "CentOS",
  rocky: "Rocky Linux",
  fedora: "Fedora",
  ubuntu: "Ubuntu",
  debian: "Debian"
};

export function osDisplayName(id?: string | null): string {
  return id ? OS_NAMES[id] ?? id.replaceAll("_", " ") : "Unknown platform";
}
