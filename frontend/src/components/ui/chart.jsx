import * as React from "react"
import { ResponsiveContainer } from "recharts"

const ChartContainer = React.forwardRef(({ className, children, ...props }, ref) => (
  // 🌟 h-full ve w-full ekleyerek üst kartın içine tam oturmasını sağlıyoruz
  <div ref={ref} className={`w-full h-full ${className}`} {...props}>
    {/* 🌟 minHeight ve minWidth vererek recharts'ın 0px olma hatasını çözüyoruz */}
    <ResponsiveContainer width="100%" height="100%" minHeight={150}>
      {children}
    </ResponsiveContainer>
  </div>
))
ChartContainer.displayName = "ChartContainer"

const ChartTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-2 shadow-md font-mono text-xs text-slate-200">
        <p className="font-semibold text-slate-400">{label}</p>
        <p className="text-cyan-400">Log Adedi: {payload[0].value}</p>
      </div>
    )
  }
  return null
}

export { ChartContainer, ChartTooltip }
