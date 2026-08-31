import { ImageResponse } from "next/og";

// Runs on the default Node.js runtime (next/og supports it). Declaring
// `runtime = "edge"` only disables static generation and emits a build warning.
export const alt = "EATHERIA - Next-Gen AI Security Platform";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          height: "100%",
          width: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          background: "linear-gradient(135deg, #0f172a 0%, #1e1b4b 40%, #0f172a 100%)",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        {/* Decorative circles */}
        <div
          style={{
            position: "absolute",
            top: -80,
            right: -80,
            width: 300,
            height: 300,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(6,182,212,0.2) 0%, transparent 70%)",
            display: "flex",
          }}
        />
        <div
          style={{
            position: "absolute",
            bottom: -60,
            left: -60,
            width: 250,
            height: 250,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(139,92,246,0.2) 0%, transparent 70%)",
            display: "flex",
          }}
        />

        {/* Logo / Title */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 16,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 16,
            }}
          >
            <div
              style={{
                width: 64,
                height: 64,
                borderRadius: 16,
                background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 36,
                fontWeight: 800,
                color: "white",
              }}
            >
              A
            </div>
            <span
              style={{
                fontSize: 72,
                fontWeight: 800,
                background: "linear-gradient(135deg, #06b6d4, #8b5cf6, #ec4899)",
                backgroundClip: "text",
                color: "transparent",
              }}
            >
              EATHERIA
            </span>
          </div>

          <span
            style={{
              fontSize: 28,
              color: "#94a3b8",
              letterSpacing: 6,
              textTransform: "uppercase",
            }}
          >
            Security Platform
          </span>

          {/* Feature pills */}
          <div
            style={{
              display: "flex",
              gap: 12,
              marginTop: 32,
            }}
          >
            {["SAST", "DAST", "SCA", "AI-Powered", "OWASP"].map((label) => (
              <div
                key={label}
                style={{
                  padding: "8px 20px",
                  borderRadius: 100,
                  border: "1px solid rgba(6,182,212,0.3)",
                  background: "rgba(6,182,212,0.1)",
                  color: "#22d3ee",
                  fontSize: 18,
                  fontWeight: 600,
                }}
              >
                {label}
              </div>
            ))}
          </div>

          <span
            style={{
              marginTop: 24,
              fontSize: 20,
              color: "#64748b",
            }}
          >
            Enterprise security powered by AI — The Fortify alternative
          </span>
        </div>
      </div>
    ),
    { ...size }
  );
}
