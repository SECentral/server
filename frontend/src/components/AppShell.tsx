import { useState, type ReactNode, type Ref } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Dropdown,
  DropdownItem,
  DropdownList,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  type MenuToggleElement,
  Nav,
  NavItem,
  NavList,
  Page,
  PageSection,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
  Toolbar,
  ToolbarContent,
  ToolbarItem
} from "@patternfly/react-core";
import { deleteSession } from "../api/sessions";
import { useSession } from "../hooks/useSession";

const NAV_ITEMS = [
  { to: "/", label: "Overview" },
  { to: "/issues", label: "SELinux issues" },
  { to: "/hosts", label: "Monitored servers" },
  { to: "/catalogs", label: "Catalogs" },
  { to: "/configuration", label: "SELinux configuration" }
];

export function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const session = useSession();
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const isActive = (to: string) =>
    to === "/" ? location.pathname === "/" : location.pathname === to || location.pathname.startsWith(`${to}/`);

  const signOut = async () => {
    try {
      await deleteSession();
    } catch {
      // Session already gone; the redirect below still applies.
    }
    await queryClient.invalidateQueries({ queryKey: ["session"] });
    navigate("/login");
  };

  return (
    <Page
      className="app-page"
      isManagedSidebar
      masthead={
        <Masthead>
          <MastheadMain>
            <MastheadToggle>
              <PageToggleButton aria-label="Toggle navigation" isHamburgerButton />
            </MastheadToggle>
            <MastheadBrand>
              <Link to="/" className="pf-v6-c-masthead__brand">
                SECentral
              </Link>
            </MastheadBrand>
          </MastheadMain>
          <MastheadContent className="app-masthead-content">
            <Toolbar className="app-masthead-toolbar">
              <ToolbarContent>
                <ToolbarItem visibility={{ default: "hidden", md: "visible" }}>SELinux observability</ToolbarItem>
                <ToolbarItem align={{ default: "alignEnd" }}>
                  <Dropdown
                    isOpen={userMenuOpen}
                    onOpenChange={setUserMenuOpen}
                    onSelect={() => {
                      setUserMenuOpen(false);
                      void signOut();
                    }}
                    popperProps={{ position: "right" }}
                    toggle={(toggleRef: Ref<MenuToggleElement>) => (
                      <MenuToggle ref={toggleRef} onClick={() => setUserMenuOpen(!userMenuOpen)} isExpanded={userMenuOpen}>
                        {session.data?.operator.username ?? "Operator"}
                      </MenuToggle>
                    )}
                  >
                    <DropdownList>
                      <DropdownItem value="sign-out">Sign out</DropdownItem>
                    </DropdownList>
                  </Dropdown>
                </ToolbarItem>
              </ToolbarContent>
            </Toolbar>
          </MastheadContent>
        </Masthead>
      }
      sidebar={
        <PageSidebar>
          <PageSidebarBody>
            <Nav aria-label="Primary navigation">
              <NavList>
                {NAV_ITEMS.map((item) => (
                  <NavItem key={item.to} isActive={isActive(item.to)}>
                    <Link to={item.to}>{item.label}</Link>
                  </NavItem>
                ))}
              </NavList>
            </Nav>
          </PageSidebarBody>
        </PageSidebar>
      }
    >
      <PageSection className="app-page-section" isPlain>{children}</PageSection>
    </Page>
  );
}
