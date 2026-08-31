"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { Logo } from "@/components/brand/logo";
import { cn } from "@/lib/utils";
import { useTheme } from "@/components/providers/theme-provider";
import { useLanguage } from "@/components/providers/language-provider";
import { LanguageSwitcher } from "@/components/ui/language-switcher";
import {
  LayoutDashboard,
  Shield,
  AppWindow,
  Scan,
  Bug,
  GitBranch,
  Users,
  Settings,
  BarChart3,
  Brain,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Menu,
  X,
  Bell,
  Search,
  ChevronDown,
  Database,
  Lock,
  Sun,
  Moon,
  Workflow,
  Cpu,
  Plug,
  SlidersHorizontal,
  MessageSquare,
  Headset,
  ShieldAlert,
  Award,
} from "lucide-react";

interface NavItem {
  title: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  adminOnly?: boolean;
  systemAdminOnly?: boolean;
  indent?: boolean;
  matchPrefix?: boolean;
}

function useNav() {
  const { t } = useLanguage();

  const PRINCIPAL_NAV: NavItem[] = [
    { title: t("dashboard.nav.dashboard"), href: "/dashboard", icon: LayoutDashboard },
    { title: t("dashboard.nav.applications"), href: "/dashboard/applications", icon: AppWindow },
    { title: t("dashboard.nav.analyses"), href: "/dashboard/analyses", icon: Scan },
    { title: t("dashboard.nav.vulnerabilities"), href: "/dashboard/vulnerabilities", icon: Bug },
    { title: "GitHub", href: "/dashboard/github", icon: GitBranch },
    { title: t("dashboard.nav.catalog"), href: "/dashboard/catalog", icon: Database },
    { title: t("dashboard.nav.standards"), href: "/dashboard/standards", icon: Award },
  ];

  const INTEGRATIONS_NAV: NavItem[] = [
    { title: "CI/CD", href: "/dashboard/integrations/cicd", icon: Workflow },
    { title: t("dashboard.nav.mcp"), href: "/dashboard/integrations/mcp", icon: Cpu },
  ];

  const ADMIN_NAV: NavItem[] = [
    { title: t("dashboard.nav.users"), href: "/dashboard/users", icon: Users, adminOnly: true },
    { title: t("dashboard.nav.aiConfig"), href: "/admin/settings/ai", icon: SlidersHorizontal, adminOnly: true, systemAdminOnly: true },
  ];

  const SYSTEM_NAV: NavItem[] = [
    { title: t("dashboard.nav.adminPanel"), href: "/admin", icon: Shield, systemAdminOnly: true },
    { title: t("dashboard.nav.aiEngine"), href: "/admin/ai-configuration", icon: Brain, systemAdminOnly: true },
    { title: t("dashboard.nav.tokens"), href: "/admin/tokens", icon: BarChart3, systemAdminOnly: true },
    { title: t("dashboard.nav.security"), href: "/admin/security", icon: Lock, systemAdminOnly: true },
    { title: t("dashboard.nav.messaging"), href: "/admin/messaging", icon: MessageSquare, systemAdminOnly: true },
    { title: t("dashboard.nav.knowledge"), href: "/admin/knowledge", icon: Brain, systemAdminOnly: true },
    { title: t("dashboard.nav.falsePositives"), href: "/admin/false-positives", icon: ShieldAlert, systemAdminOnly: true },
    { title: t("dashboard.nav.settings"), href: "/admin/settings", icon: Settings, systemAdminOnly: true },
  ];

  return { PRINCIPAL_NAV, INTEGRATIONS_NAV, ADMIN_NAV, SYSTEM_NAV };
}

interface DashboardUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isSystemAdmin: boolean;
  isCompanyAdmin?: boolean;
  avatarUrl?: string | null;
  companyId?: string | null;
}

export function DashboardShell({
  children,
  user,
}: {
  children: React.ReactNode;
  user: DashboardUser;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const { update } = useSession();
  const { theme, toggleTheme } = useTheme();
  const { t } = useLanguage();
  const { PRINCIPAL_NAV, INTEGRATIONS_NAV, ADMIN_NAV, SYSTEM_NAV } = useNav();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<{ type: string; id: string; title: string; subtitle: string; href: string }[]>([]);
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<{ id: string; title: string; message: string; type: string; isRead: boolean; createdAt: string }[]>([]);
  const searchRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<NodeJS.Timeout | null>(null);

  const isDark = theme === "dark";


  const doSearch = useCallback(async (q: string) => {
    if (q.trim().length < 3) {
      setSearchResults([]);
      setShowSearchResults(false);
      return;
    }
    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
      if (res.ok) {
        const data = await res.json();
        setSearchResults(data.results || []);
        setShowSearchResults(true);
      }
    } catch { /* ignore */ }
  }, []);

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(value), 300);
  };

  // Close search dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowSearchResults(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  // Fetch notifications
  const fetchNotifications = useCallback(async () => {
    try {
      const res = await fetch("/api/notifications?limit=10");
      if (res.ok) {
        const data = await res.json();
        setUnreadCount(data.unreadCount || 0);
        setNotifications(data.notifications || []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    // Initial fetch via interval tick (avoids direct setState in effect body)
    const interval = setInterval(fetchNotifications, 30000);
    fetchNotifications();
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const markAllRead = async () => {
    try {
      await fetch("/api/notifications", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ markAllRead: true }),
      });
      setUnreadCount(0);
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
    } catch { /* ignore */ }
  };

  return (
    <div className="min-h-screen flex transition-colors duration-300 dashboard-bg">
      {/* Ambient orbs — login atmosphere, toned down. Behind everything. */}
      <div className="dashboard-orb dashboard-orb-primary" />
      <div className="dashboard-orb dashboard-orb-secondary" />

      {/* Mobile Overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed md:sticky top-0 left-0 z-50 h-screen flex flex-col transition-all duration-300",
          isDark
            ? "bg-sidebar-bg border-r border-border"
            : "bg-white border-r border-border shadow-sm",
          collapsed ? "w-[72px]" : "w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        {/* Logo */}
        <div className={cn("h-16 flex items-center justify-between px-4 border-b", isDark ? "border-border" : "border-border")}>
          <Logo showText={!collapsed} size="sm" />
          <button
            onClick={() => setCollapsed(!collapsed)}
            className={cn("hidden md:flex h-7 w-7 items-center justify-center rounded-md transition-colors", isDark ? "hover:bg-surface-hover text-text-secondary" : "hover:bg-surface-hover text-text-muted")}
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
          <button onClick={() => setMobileOpen(false)} className="md:hidden text-text-secondary">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
          <NavGroup label={t("dashboard.nav.principal")} collapsed={collapsed} isDark={isDark}>
            {PRINCIPAL_NAV.map((item) => (
              <NavLink key={item.href} item={item} active={pathname === item.href} collapsed={collapsed} isDark={isDark} onClick={() => setMobileOpen(false)} />
            ))}
          </NavGroup>

          <NavGroup label={t("dashboard.nav.integrations")} collapsed={collapsed} isDark={isDark}>
            {INTEGRATIONS_NAV.map((item) => (
              <NavLink key={item.href} item={item} active={pathname.startsWith(item.href)} collapsed={collapsed} isDark={isDark} onClick={() => setMobileOpen(false)} />
            ))}
          </NavGroup>

          <CollapsibleNavGroup label={t("dashboard.nav.administration")} collapsed={collapsed} isDark={isDark} pathname={pathname} matchPrefix="/dashboard/users" matchPaths={["/admin/settings/ai"]}>
            {ADMIN_NAV.filter((item) => !item.systemAdminOnly || user.isSystemAdmin).map((item) => (
              <NavLink key={item.href} item={item} active={item.matchPrefix ? pathname.startsWith(item.href) : pathname === item.href} collapsed={collapsed} isDark={isDark} onClick={() => setMobileOpen(false)} />
            ))}
          </CollapsibleNavGroup>

          {user.isSystemAdmin && (
            <CollapsibleNavGroup label={t("dashboard.nav.system")} collapsed={collapsed} isDark={isDark} pathname={pathname} matchPrefix="/admin">
              {SYSTEM_NAV.map((item) => (
                <NavLink key={item.href} item={item} active={pathname.startsWith(item.href)} collapsed={collapsed} isDark={isDark} onClick={() => setMobileOpen(false)} />
              ))}
            </CollapsibleNavGroup>
          )}
        </nav>

        {/* User */}
        <div className={cn("border-t p-3", isDark ? "border-border" : "border-border")}>
          <div className={cn("flex items-center gap-3 rounded-lg p-2", !collapsed && (isDark ? "hover:bg-white/[0.04]" : "hover:bg-surface-hover"))}>
            <div className="h-8 w-8 rounded-full bg-gradient-to-br from-cyan-500 to-purple-500 flex items-center justify-center text-white font-bold text-xs shrink-0">
              {user.firstName[0]}{user.lastName[0]}
            </div>
            {!collapsed && (
              <div className="flex-1 min-w-0">
                <p className={cn("text-sm font-semibold truncate", isDark ? "text-text-primary" : "text-text-primary")}>
                  {user.firstName} {user.lastName}
                </p>
                <p className={cn("text-xs truncate", isDark ? "text-text-secondary" : "text-text-muted")}>{user.email}</p>
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className={cn(
          "sticky top-0 z-30 h-16 flex items-center justify-between px-6 backdrop-blur-xl border-b transition-colors duration-300",
          isDark ? "bg-topbar-bg border-border" : "bg-topbar-bg border-border"
        )}>
          <div className="flex items-center gap-4">
            <button onClick={() => setMobileOpen(true)} className={cn("md:hidden transition-colors", isDark ? "text-text-secondary hover:text-text-primary" : "text-text-muted hover:text-text-primary")}>
              <Menu className="h-5 w-5" />
            </button>
            <div className="relative hidden sm:block" ref={searchRef}>
              <Search className={cn("absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4", isDark ? "text-text-muted" : "text-text-secondary")} />
              <input
                type="text"
                placeholder={t("dashboard.header.search")}
                value={searchQuery}
                onChange={(e) => handleSearchChange(e.target.value)}
                onFocus={() => { if (searchResults.length > 0) setShowSearchResults(true); }}
                className={cn(
                  "h-9 w-64 rounded-lg border pl-9 pr-4 text-sm focus:outline-none focus:ring-2 transition-colors",
                  isDark
                    ? "border-border bg-surface text-text-primary placeholder:text-text-muted focus:ring-cyan-500/30 focus:border-cyan-500/30"
                    : "border-border bg-slate-50 text-text-primary placeholder:text-text-secondary focus:ring-cyan-500/30 focus:border-cyan-400"
                )}
              />
              {showSearchResults && searchResults.length > 0 && (
                <div className={cn(
                  "absolute top-11 left-0 w-80 rounded-lg border shadow-xl z-50 overflow-hidden",
                  isDark ? "bg-card border-border" : "bg-white border-border"
                )}>
                  {searchResults.map((r) => (
                    <Link
                      key={`${r.type}-${r.id}`}
                      href={r.href}
                      onClick={() => { setShowSearchResults(false); setSearchQuery(""); }}
                      className={cn(
                        "block px-4 py-3 border-b last:border-b-0 transition-colors",
                        isDark ? "border-border hover:bg-surface" : "border-border hover:bg-surface-hover"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium", isDark ? "bg-cyan-500/20 text-accent" : "bg-cyan-100 text-cyan-700")}>
                          {r.type === "application" ? "App" : r.type === "analysis" ? "Análisis" : "Vuln"}
                        </span>
                        <span className={cn("text-sm font-medium truncate", isDark ? "text-text-primary" : "text-text-primary")}>{r.title}</span>
                      </div>
                      <p className={cn("text-xs mt-0.5", isDark ? "text-text-muted" : "text-text-secondary")}>{r.subtitle}</p>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Language */}
            <LanguageSwitcher compact />

            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className={cn(
                "h-9 w-9 rounded-lg border flex items-center justify-center transition-all duration-300 hover:scale-105",
                isDark
                  ? "border-border hover:bg-surface-hover text-text-secondary hover:text-amber-400"
                  : "border-border hover:bg-surface-hover text-text-muted hover:text-indigo-600"
              )}
              title={isDark ? t("dashboard.header.lightMode") : t("dashboard.header.darkMode")}
            >
              {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            {/* Notifications */}
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => setShowNotifications(!showNotifications)}
                className={cn(
                  "relative h-9 w-9 rounded-lg border flex items-center justify-center transition-colors",
                  isDark ? "border-border hover:bg-surface-hover text-text-secondary hover:text-text-primary" : "border-border hover:bg-surface-hover text-text-muted hover:text-text-primary"
                )}
              >
                <Bell className="h-4 w-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-cyan-500 text-[10px] font-bold flex items-center justify-center text-white">
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                )}
              </button>
              {showNotifications && (
                <div className={cn(
                  "absolute right-0 top-11 w-80 rounded-lg border shadow-xl z-50 overflow-hidden",
                  isDark ? "bg-card border-border" : "bg-white border-border"
                )}>
                  <div className={cn("flex items-center justify-between px-4 py-3 border-b", isDark ? "border-border" : "border-border")}>
                    <span className={cn("text-sm font-semibold", isDark ? "text-text-primary" : "text-text-primary")}>Notificaciones</span>
                    {unreadCount > 0 && (
                      <button onClick={markAllRead} className="text-xs text-accent hover:text-accent">Marcar todas leídas</button>
                    )}
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <p className={cn("text-sm text-center py-6", isDark ? "text-text-muted" : "text-text-secondary")}>Sin notificaciones</p>
                    ) : (
                      notifications.map((n) => (
                        <div key={n.id} className={cn("px-4 py-3 border-b last:border-b-0", isDark ? "border-border" : "border-border", !n.isRead && (isDark ? "bg-cyan-500/5" : "bg-cyan-50"))}>
                          <p className={cn("text-sm font-medium", isDark ? "text-text-primary" : "text-text-primary")}>{n.title}</p>
                          <p className={cn("text-xs mt-0.5", isDark ? "text-text-secondary" : "text-text-muted")}>{n.message}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* User dropdown */}
            <div className="relative group">
              <button className={cn(
                "flex items-center gap-2 h-9 rounded-lg border px-3 transition-colors",
                isDark ? "border-border hover:bg-surface-hover text-text-primary hover:text-text-primary" : "border-border hover:bg-surface-hover text-text-muted hover:text-text-primary"
              )}>
                <div className="h-6 w-6 rounded-full bg-gradient-to-br from-cyan-500 to-purple-500 flex items-center justify-center text-white font-bold text-[10px]">
                  {user.firstName[0]}{user.lastName[0]}
                </div>
                <span className="hidden sm:inline text-sm">{user.firstName}</span>
                <ChevronDown className="h-3 w-3" />
              </button>

              <div className={cn(
                "absolute right-0 top-full mt-2 w-48 rounded-lg border shadow-2xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all",
                isDark ? "border-border bg-surface" : "border-border bg-white"
              )}>
                <div className="p-2">
                  <Link
                    href="/dashboard/profile"
                    className={cn("flex items-center gap-2 px-3 py-2 rounded-md text-sm", isDark ? "text-text-primary hover:bg-surface-hover hover:text-text-primary" : "text-text-muted hover:bg-surface-hover hover:text-text-primary")}
                  >
                    <Settings className="h-4 w-4" />
                    {t("common.profile")}
                  </Link>
                  <button
                    onClick={() => signOut({ callbackUrl: "/login" })}
                    className="flex items-center gap-2 w-full px-3 py-2 rounded-md text-sm text-red-400 hover:bg-red-500/10"
                  >
                    <LogOut className="h-4 w-4" />
                    {t("common.logout")}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 p-6 overflow-auto">{children}</main>
      </div>
    </div>
  );
}

function NavGroup({ label, collapsed, isDark, children }: { label: string; collapsed: boolean; isDark: boolean; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      {!collapsed && (
        <p className={cn("px-3 pt-4 pb-1 text-[10px] font-bold uppercase tracking-wider", isDark ? "text-text-muted" : "text-text-secondary")}>
          {label}
        </p>
      )}
      {collapsed && <div className="h-2" />}
      {children}
    </div>
  );
}

function CollapsibleNavGroup({ label, collapsed, isDark, children, pathname, matchPrefix, matchPaths }: {
  label: string; collapsed: boolean; isDark: boolean; children: React.ReactNode;
  pathname: string; matchPrefix: string; matchPaths?: string[];
}) {
  const isActive = pathname.startsWith(matchPrefix) || (matchPaths || []).some((p) => pathname.startsWith(p));
  const [manualToggle, setManualToggle] = useState<boolean | null>(null);
  const open = manualToggle !== null ? manualToggle : isActive;

  if (collapsed) {
    return (
      <div className="space-y-1">
        <div className="h-2" />
        {children}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <button
        onClick={() => setManualToggle(!open)}
        className={cn(
          "w-full flex items-center justify-between px-3 pt-4 pb-1 text-[10px] font-bold uppercase tracking-wider transition-colors",
          isDark ? "text-text-muted hover:text-text-primary" : "text-text-secondary hover:text-text-muted"
        )}
      >
        {label}
        <ChevronDown className={cn("h-3 w-3 transition-transform duration-200", open && "rotate-180")} />
      </button>
      <div className={cn("overflow-hidden transition-all duration-200", open ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0")}>
        {children}
      </div>
    </div>
  );
}

function NavLink({ item, active, collapsed, isDark, onClick }: { item: NavItem; active: boolean; collapsed: boolean; isDark: boolean; onClick?: () => void }) {
  return (
    <Link
      href={item.href}
      scroll={false}
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all",
        active
          ? isDark
            ? "bg-gradient-to-r from-cyan-500/15 to-purple-500/10 text-accent border border-cyan-500/20"
            : "bg-gradient-to-r from-cyan-50 to-purple-50 text-cyan-700 border border-cyan-200/60"
          : isDark
            ? "text-text-secondary hover:text-text-primary hover:bg-white/[0.04]"
            : "text-text-muted hover:text-text-primary hover:bg-surface-hover",
        collapsed && "justify-center px-2",
        item.indent && !collapsed && "ml-4 py-2 text-xs"
      )}
      title={collapsed ? item.title : undefined}
    >
      <item.icon className={cn("h-5 w-5 shrink-0", active && (isDark ? "text-accent" : "text-cyan-600"), item.indent && "h-4 w-4")} />
      {!collapsed && <span>{item.title}</span>}
    </Link>
  );
}
