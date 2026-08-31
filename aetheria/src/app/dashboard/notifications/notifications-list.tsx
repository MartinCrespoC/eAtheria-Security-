"use client";

import { useState } from "react";
import Link from "next/link";
import { Bell, BellOff, CheckCheck, Shield, AlertTriangle, Info, ExternalLink, Trash2 } from "lucide-react";

interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  isRead: boolean;
  createdAt: string;
  readAt: string | null;
  metadata: Record<string, unknown> | null;
}

function TypeIcon({ type }: { type: string }) {
  switch (type) {
    case "scan_complete":
    case "pr_scanned":
      return <Shield className="w-4 h-4 text-accent" />;
    case "vuln_found":
      return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
    case "warning":
    case "error":
      return <AlertTriangle className="w-4 h-4 text-red-400" />;
    default:
      return <Info className="w-4 h-4 text-blue-400" />;
  }
}

function formatTimeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString();
}

export function NotificationsList({ notifications }: { notifications: Notification[] }) {
  const [items, setItems] = useState(notifications);
  const [markingAll, setMarkingAll] = useState(false);

  const unreadCount = items.filter((n) => !n.isRead).length;

  async function markAsRead(id: string) {
    try {
      const res = await fetch(`/api/notifications/${id}`, { method: "PATCH" });
      if (res.ok) {
        setItems((prev) => prev.map((n) => (n.id === id ? { ...n, isRead: true } : n)));
      }
    } catch (err) {
      console.error("Failed to mark notification:", err);
    }
  }

  async function markAllRead() {
    setMarkingAll(true);
    try {
      const res = await fetch("/api/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ markAll: true }),
      });
      if (res.ok) {
        setItems((prev) => prev.map((n) => ({ ...n, isRead: true })));
      }
    } catch (err) {
      console.error("Failed to mark all:", err);
    } finally {
      setMarkingAll(false);
    }
  }

  async function deleteNotification(id: string) {
    try {
      const res = await fetch(`/api/notifications/${id}`, { method: "DELETE" });
      if (res.ok) {
        setItems((prev) => prev.filter((n) => n.id !== id));
      }
    } catch (err) {
      console.error("Failed to delete notification:", err);
    }
  }

  function getNotificationLink(n: Notification): string | null {
    if (n.metadata?.analysisId) {
      return `/dashboard/analyses/${n.metadata.analysisId}`;
    }
    return null;
  }

  return (
    <div className="space-y-4">
      {/* Actions bar */}
      {unreadCount > 0 && (
        <div className="flex items-center justify-end">
          <button
            onClick={markAllRead}
            disabled={markingAll}
            className="flex items-center gap-2 px-3 py-1.5 text-xs text-accent border border-cyan-500/30 rounded-lg hover:bg-cyan-500/10 transition-colors disabled:opacity-50"
          >
            <CheckCheck className="w-3.5 h-3.5" />
            Mark all as read
          </button>
        </div>
      )}

      {/* List */}
      {items.length === 0 ? (
        <div className="text-center py-12 text-text-muted">
          <BellOff className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No notifications yet</p>
        </div>
      ) : (
        <div className="space-y-1">
          {items.map((n) => {
            const link = getNotificationLink(n);
            return (
              <div
                key={n.id}
                className={`group flex items-start gap-3 p-3 rounded-lg border transition-colors ${
                  n.isRead
                    ? "bg-surface border-border"
                    : "bg-surface border-cyan-500/20"
                }`}
              >
                <div className="mt-0.5 shrink-0">
                  <TypeIcon type={n.type} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h4 className={`text-sm font-medium truncate ${n.isRead ? "text-text-primary" : "text-text-primary"}`}>
                      {n.title}
                    </h4>
                    {!n.isRead && <span className="w-2 h-2 bg-cyan-400 rounded-full shrink-0" />}
                  </div>
                  <p className="text-xs text-text-secondary mt-0.5 line-clamp-2">{n.message}</p>
                  <span className="text-xs text-text-muted mt-1">{formatTimeAgo(n.createdAt)}</span>
                </div>
                <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                  {link && (
                    <Link
                      href={link}
                      className="p-1.5 text-text-secondary hover:text-accent transition-colors"
                      title="View details"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </Link>
                  )}
                  {!n.isRead && (
                    <button
                      onClick={() => markAsRead(n.id)}
                      className="p-1.5 text-text-secondary hover:text-emerald-400 transition-colors"
                      title="Mark as read"
                    >
                      <CheckCheck className="w-3.5 h-3.5" />
                    </button>
                  )}
                  <button
                    onClick={() => deleteNotification(n.id)}
                    className="p-1.5 text-text-secondary hover:text-red-400 transition-colors"
                    title="Delete"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
