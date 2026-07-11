"use client"

import { useEffect, useState } from "react"
import QRCode from "qrcode"

export const BOT_USERNAME = "Octupus_cve_bot"
export const BOT_URL = `https://t.me/${BOT_USERNAME}`

export function TelegramQR({ size = 168 }: { size?: number }) {
  const [src, setSrc] = useState<string>("")

  useEffect(() => {
    QRCode.toDataURL(BOT_URL, {
      margin: 1,
      width: size * 2,
      color: { dark: "#0a0e1a", light: "#ffffff" },
      errorCorrectionLevel: "M",
    })
      .then(setSrc)
      .catch(() => setSrc(""))
  }, [size])

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="rounded-2xl bg-white p-3 shadow-[0_0_30px_rgba(56,189,248,0.35)] ring-1 ring-cyan-400/40">
        {src ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={src} alt={`QR OCTUPUS Telegram bot @${BOT_USERNAME}`} width={size} height={size} className="block rounded-lg" />
        ) : (
          <div style={{ width: size, height: size }} className="animate-pulse rounded-lg bg-slate-200" />
        )}
      </div>
      <a
        href={BOT_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="rounded-full bg-gradient-to-r from-cyan-500 to-sky-600 px-4 py-1.5 text-sm font-semibold text-white shadow-[0_4px_20px_rgba(56,189,248,0.4)]"
      >
        Ouvrir @{BOT_USERNAME}
      </a>
    </div>
  )
}
