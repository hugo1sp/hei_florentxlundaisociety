"use client";

import { useEffect, useState } from "react";

const CHECKS = [
  { label: "Probing for exposed secret files",  delay: 0     },
  { label: "Checking SSL certificate",           delay: 1200  },
  { label: "Scanning for open ports",            delay: 2500  },
  { label: "Inspecting admin panels",            delay: 4000  },
  { label: "Analysing HTTP security headers",    delay: 5500  },
  { label: "Checking DNS & email records",       delay: 7000  },
  { label: "Inspecting cookies",                 delay: 8500  },
  { label: "Testing CORS policy",                delay: 10000 },
  { label: "Scanning subdomains",                delay: 12000 },
  { label: "Checking for data breaches",         delay: 14000 },
  { label: "Scanning GitHub workflows",          delay: 16000 },
];

export default function LoadingState({ fixedMessage }: { fixedMessage?: string }) {
  const [done, setDone] = useState<Set<number>>(new Set());

  useEffect(() => {
    if (fixedMessage) {
      setDone(new Set(CHECKS.map((_, i) => i)));
      return;
    }
    setDone(new Set());
    const timers = CHECKS.map((c, i) =>
      setTimeout(() => setDone(prev => new Set([...prev, i])), c.delay)
    );
    return () => timers.forEach(clearTimeout);
  }, [fixedMessage]);

  return (
    <div className="w-full max-w-xs mx-auto py-12 space-y-2.5">
      {CHECKS.map((c, i) => {
        const isDone = done.has(i);
        const isNext = !isDone && done.size === i;
        return (
          <div
            key={i}
            className={`flex items-center gap-3 transition-opacity duration-300 ${
              isDone || isNext ? "opacity-100" : "opacity-25"
            }`}
          >
            <span className={`w-5 h-5 flex-shrink-0 flex items-center justify-center rounded-full text-xs font-bold transition-all duration-300 ${
              isDone
                ? "bg-green-900 text-green-400"
                : isNext
                ? "bg-gray-800 text-blue-400 animate-pulse"
                : "bg-gray-800 text-gray-600"
            }`}>
              {isDone ? "✓" : "○"}
            </span>
            <span className={`text-sm transition-colors duration-300 ${
              isDone
                ? "text-gray-500 line-through decoration-gray-600"
                : isNext
                ? "text-white font-medium"
                : "text-gray-600"
            }`}>
              {c.label}
            </span>
          </div>
        );
      })}
      {fixedMessage && (
        <p className="text-center text-sm text-indigo-400 pt-4 animate-pulse">{fixedMessage}</p>
      )}
    </div>
  );
}
