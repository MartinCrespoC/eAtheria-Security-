"use client";

import { useState } from "react";

export function UnblockButton({ userId }: { userId: string }) {
  const [loading, setLoading] = useState(false);

  const handleUnblock = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/users/${userId}/block`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ block: false }),
      });
      if (res.ok) {
        window.location.reload();
      } else {
        alert("Error al desbloquear usuario");
      }
    } catch {
      alert("Error de conexión");
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleUnblock}
      disabled={loading}
      className="px-3 py-1.5 text-xs font-medium rounded-lg bg-green-500/20 text-green-400 hover:bg-green-500/30 border border-green-500/30 transition-colors disabled:opacity-50"
    >
      {loading ? "..." : "Desbloquear"}
    </button>
  );
}
