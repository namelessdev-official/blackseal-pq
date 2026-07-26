import type { ReactNode } from "react";
import { cn } from "../utils/cn";

export function Panel({
  title,
  tag,
  children,
  className,
}: {
  title?: string;
  tag?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cn(
        "relative border border-emerald-900/60 bg-[#070b0c]/85 backdrop-blur-sm clip-corner",
        className,
      )}
    >
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-emerald-900/50 px-4 py-2">
          <h2 className="text-[11px] tracking-[0.35em] text-emerald-400/90">
            {title}
          </h2>
          {tag}
        </header>
      )}
      <div className="p-4 md:p-5">{children}</div>
    </section>
  );
}

export function Label({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <div className="mb-1.5 flex items-baseline justify-between">
      <label className="text-[10px] tracking-[0.28em] text-emerald-500/70">
        {children}
      </label>
      {hint && <span className="text-[10px] text-zinc-600">{hint}</span>}
    </div>
  );
}

const fieldBase =
  "w-full bg-black/60 border border-emerald-900/60 px-3 py-2.5 text-sm text-emerald-50 placeholder:text-zinc-700 outline-none transition focus:border-emerald-500/70 focus:shadow-[0_0_0_1px_rgba(16,185,129,0.35),0_0_22px_-6px_rgba(16,185,129,0.7)]";

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn(fieldBase, props.className)} />;
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={cn(fieldBase, "resize-y leading-relaxed", props.className)}
    />
  );
}

export function Button({
  children,
  variant = "primary",
  className,
  ...rest
}: {
  variant?: "primary" | "ghost" | "danger";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const styles = {
    primary:
      "bg-emerald-500/15 border-emerald-500/60 text-emerald-300 hover:bg-emerald-500/25 hover:text-emerald-100",
    ghost:
      "bg-transparent border-emerald-900/70 text-emerald-600 hover:border-emerald-600/70 hover:text-emerald-300",
    danger:
      "bg-red-500/10 border-red-500/50 text-red-300 hover:bg-red-500/20",
  }[variant];
  return (
    <button
      {...rest}
      className={cn(
        "border px-4 py-2.5 text-[11px] tracking-[0.22em] uppercase transition disabled:cursor-not-allowed disabled:opacity-35",
        styles,
        className,
      )}
    >
      {children}
    </button>
  );
}

export function Stat({ k, v, accent }: { k: string; v: ReactNode; accent?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-dashed border-emerald-950 py-1.5 last:border-0">
      <span className="text-[10px] tracking-[0.2em] text-zinc-600">{k}</span>
      <span
        className={cn(
          "truncate text-right text-[11px]",
          accent ? "text-emerald-300" : "text-zinc-400",
        )}
      >
        {v}
      </span>
    </div>
  );
}
