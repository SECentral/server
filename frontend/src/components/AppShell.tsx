import { useState, type ReactNode, type Ref } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Button,
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
import { GithubIcon, MoonIcon, SunIcon } from "@patternfly/react-icons";
import { deleteSession } from "../api/sessions";
import { useSession } from "../hooks/useSession";
import logo from "../assets/secentral-logo.svg";

const NAV_ITEMS = [
  { to: "/", label: "Overview" },
  { to: "/issues", label: "SELinux issues" },
  { to: "/log", label: "Global log" },
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
  const [isDarkTheme, setIsDarkTheme] = useState(() => localStorage.getItem("theme") !== "light");

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

  const toggleTheme = () => {
    const nextIsDark = !isDarkTheme;
    document.documentElement.classList.toggle("pf-v6-theme-dark", nextIsDark);
    localStorage.setItem("theme", nextIsDark ? "dark" : "light");
    setIsDarkTheme(nextIsDark);
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
              <Link to="/" className="pf-v6-c-masthead__brand" aria-label="SECentral home">
                <img className="app-brand-logo" src={logo} alt="SECentral" width="192" height="52" />
              </Link>
            </MastheadBrand>
          </MastheadMain>
          <MastheadContent className="app-masthead-content">
            <Toolbar className="app-masthead-toolbar">
              <ToolbarContent>
                <ToolbarItem className="app-masthead-actions" align={{ default: "alignEnd" }}>
                  <Button
                    component="a"
                    variant="plain"
                    href="https://github.com/SECentral/server"
                    target="_blank"
                    rel="noreferrer"
                    aria-label="SECentral server on GitHub (opens in a new tab)"
                    icon={<GithubIcon aria-hidden="true" />}
                  />
                  <Button
                    variant="plain"
                    onClick={toggleTheme}
                    aria-label={`Switch to ${isDarkTheme ? "light" : "dark"} mode`}
                    icon={isDarkTheme ? <SunIcon aria-hidden="true" /> : <MoonIcon aria-hidden="true" />}
                  />
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
