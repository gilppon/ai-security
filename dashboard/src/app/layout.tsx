import type { Metadata } from "next";
import { Inter, Space_Grotesk, JetBrains_Mono, Noto_Sans_KR, Noto_Sans_JP } from "next/font/google";
import "./globals.css";
import { LanguageProvider } from "@/context/LanguageContext";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  weight: ["400", "500", "600", "700"],
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  weight: ["500", "600", "700"],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  weight: ["400", "500", "700"],
});

const notoSansKR = Noto_Sans_KR({
  subsets: ["latin"],
  variable: "--font-noto-kr",
  weight: ["400", "500", "700"],
});

const notoSansJP = Noto_Sans_JP({
  subsets: ["latin"],
  variable: "--font-noto-jp",
  weight: ["400", "500", "700"],
});

export const metadata: Metadata = {
  title: "AI Security Control Plane — 0.1ms In-Process SDK & Cyber War-Room",
  description: "Proprietary defensive AI security control plane intercepting LLM agent execution cycles with sub-millisecond in-process firewalls, MCP gateways, and WORM-locked audit chains.",
  keywords: [
    "AI Security",
    "Agent Security Control Plane",
    "MCP Gateway",
    "Prompt Injection Firewall",
    "In-Process AI SDK",
    "WORM Audit Trail",
    "LLM Zero Trust",
  ],
  openGraph: {
    title: "AI Security Control Plane — 0.1ms In-Process SDK & Cyber SOC",
    description: "Enterprise-grade defensive control plane for autonomous AI agents. 0.145ms latency gate with 8-stage deterministic verification.",
    type: "website",
    locale: "ko_KR",
  },
  twitter: {
    card: "summary_large_image",
    title: "AI Security Control Plane — Sub-Millisecond Agent Defense",
    description: "Defend AI agents against jailbreaks, MCP privilege escalation, and confused deputy attacks with Default Deny firewalls.",
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "@id": "https://ai-security.dev/#software",
      "name": "AI Security Control Plane",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "Linux, Windows, macOS",
      "description": "Proprietary defensive AI security control plane intercepting LLM agent execution cycles with sub-millisecond in-process firewalls, MCP gateways, and WORM-locked audit chains.",
      "softwareVersion": "3.0.0",
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD",
      },
      "featureList": [
        "0.145ms In-Process SDK (28.2x Speedup)",
        "MCP Tool Gateway & Scope Enforcement",
        "Deterministic 8-Stage Security Pipeline",
        "Plan Validator & Confused Deputy Prevention",
        "WORM Immutable Audit Trail (SHA-256 Chain + Cloudflare R2)",
        "Default Deny Principle & Structured Reason Codes",
      ],
    },
    {
      "@type": "FAQPage",
      "@id": "https://ai-security.dev/#faq",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "AI Security Control Plane이란 무엇인가요?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "자율형 AI 에이전트의 실행 주기(프롬프트, 도구 호출, 계획, 파일/네트워크 리소스)를 실시간 차단·통제하는 결정론적 보안 제어 평면입니다. LLM의 출력을 신뢰하지 않는 Default Deny 원칙을 강제합니다.",
          },
        },
        {
          "@type": "Question",
          "name": "In-Process Embedded SDK 모드의 장점은 무엇인가요?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Docker나 REST API 서버 구동 없이 파이썬 에이전트 내에서 직접 임베딩되어, HTTP 통신 오버헤드를 없애고 평균 0.145ms(기존 REST 대비 28.2배 단축)의 초저지연 보안 검사를 제공합니다.",
          },
        },
        {
          "@type": "Question",
          "name": "MCP(Model Context Protocol) 게이트웨이는 어떻게 보호하나요?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "에이전트가 호출하는 MCP 도구 매니페스트와 선언된 스코프를 검증하고, 비인가 쉘 실행이나 파일시스템 탈출, SSRF 네트워크 요청을 격리 샌드박스에서 원천 차단합니다.",
          },
        },
      ],
    },
    {
      "@type": "Organization",
      "@id": "https://ai-security.dev/#org",
      "name": "AI Security Systems",
      "url": "https://ai-security.dev",
      "knowsAbout": ["AI Agent Security", "Prompt Injection Defense", "Model Context Protocol", "WORM Auditing"],
    },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="ko"
      className={`dark ${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable} ${notoSansKR.variable} ${notoSansJP.variable}`}
    >
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className="min-h-screen bg-[#04080E] text-[#D5E5F2] antialiased selection:bg-[#00F0FF]/30 selection:text-[#00F0FF]">
        <LanguageProvider>
          {children}
        </LanguageProvider>
      </body>
    </html>
  );
}
