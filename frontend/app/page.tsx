"use client";

import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Code2,
  Terminal,
  AlertTriangle,
  Sparkles,
  RefreshCw,
  GitBranch,
  FileCode,
  CheckCircle2,
  Upload,
  RotateCcw,
  FileUp,
  Copy,
  Check,
  X,
  ExternalLink,
} from "lucide-react";

interface Finding {
  rule_id: string;
  severity: string;
  file_path: string;
  line_number: number;
  raw_message: string;
  ai_explanation?: string | null;
  ai_fix_suggestion?: string | null;
  ai_confidence?: string | null;
  severity_conflict?: boolean;
  source?: "semgrep" | "ai_only" | null;
}

interface ScanResponse {
  scan_id: number;
  status: "processing" | "done" | "error";
  language?: string;
  source_type?: string;
  findings: Finding[];
}

// Realistic language-aware insecure samples
const INSECURE_SAMPLES: Record<string, string> = {
  python: `import os
import subprocess

# 1. Insecure hardcoded credential
DB_PASSWORD = "SuperSecretAdminPassword123!"
AWS_KEY = "AKIA1234567890EXAMPLE12"

def execute_user_query(user_query, user_command):
    # 2. SQL Injection via string formatting
    sql = "SELECT * FROM users WHERE username = '%s'" % user_query
    
    # 3. Insecure shell command execution
    os.system("echo " + user_command)
    subprocess.call("ls " + user_command, shell=True)

def authenticate(user, password):
    if password == "admin_hardcoded_token":
        return True
    return False
`,

  javascript: `const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql2');
const app = express();

// 1. Insecure hardcoded secret
const JWT_SECRET = "super_secret_jwt_signing_key_98765";
const STRIPE_KEY = "sk-live-1234567890abcdef1234567890";

const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'hardcoded_db_pass_123' });

app.get('/search', (req, res) => {
    const userInput = req.query.q;
    
    // 2. Insecure eval / injection
    eval("console.log('Query: " + userInput + "')");
    
    // 3. Command injection via exec
    exec("ping -c 1 " + userInput, (err, stdout) => {
        if (err) return res.status(500).send(err.message);
        res.send(stdout);
    });
});
`,

  typescript: `import express, { Request, Response } from 'express';
import { exec } from 'child_process';

// 1. Insecure hardcoded credentials
const GITHUB_TOKEN: string = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
const API_SECRET: string = "sk-ant-api03-abcdef1234567890abcdef";

export function handleAdminAction(req: Request, res: Response): void {
    const command = req.query.cmd as string;
    
    // 2. Unsafe shell command execution
    exec(\`sh -c "\${command}"\`, (err, stdout) => {
        if (err) {
            res.status(500).send(err.message);
            return;
        }
        res.send(stdout);
    });
}
`,

  java: `import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class InsecureAccountService {
    // 1. Hardcoded credentials
    private static final String DB_PASSWORD = "HardcodedDBAdminPass2026!";
    private static final String AWS_KEY = "AKIA1234567890EXAMPLE12";

    public void processUserRequest(String username, String userCommand) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app_db", "root", DB_PASSWORD);
        
        // 2. SQL Injection via string concatenation
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        
        // 3. Insecure command execution
        Runtime.getRuntime().exec("sh -c " + userCommand);
    }
}
`,
};

const LANGUAGE_LABELS: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
  java: "Java",
};

const LANGUAGE_EXTENSIONS: Record<string, string> = {
  python: ".py",
  javascript: ".js",
  typescript: ".ts",
  java: ".java",
};

const MAX_FILE_SIZE_BYTES = 500 * 1024; // 500 KB

export default function Home() {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<"paste" | "upload" | "repo">("paste");
  const [language, setLanguage] = useState<string>("python");

  // Tab states (independent state preservation)
  const [code, setCode] = useState<string>(""); // Empty by default
  const [repoUrl, setRepoUrl] = useState<string>("");
  const [uploadedFile, setUploadedFile] = useState<{ name: string; size: number; content: string } | null>(null);

  // Drag and drop state
  const [isDragging, setIsDragging] = useState<boolean>(false);

  // Scan & Results state
  const [scanId, setScanId] = useState<number | null>(null);
  const [scanStatus, setScanStatus] = useState<"idle" | "submitting" | "processing" | "done" | "error">("idle");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  // Check if current code matches any sample
  const isSampleLoaded = useMemo(() => {
    if (!code.trim()) return false;
    return Object.values(INSECURE_SAMPLES).some((sample) => sample.trim() === code.trim());
  }, [code]);

  // Handle language dropdown change
  const handleLanguageChange = (newLang: string) => {
    setLanguage(newLang);
    // If a sample was loaded, auto-switch to the new language's sample
    if (isSampleLoaded) {
      setCode(INSECURE_SAMPLES[newLang] || "");
    }
    // If user has typed their own custom code, do NOT overwrite it!
  };

  // Load sample code button
  const handleLoadSample = () => {
    setCode(INSECURE_SAMPLES[language] || "");
    setErrorMessage(null);
  };

  // Reset / Clear button
  const handleReset = () => {
    setCode("");
    setRepoUrl("");
    setUploadedFile(null);
    setFindings([]);
    setScanId(null);
    setScanStatus("idle");
    setErrorMessage(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // File upload processing
  const handleFileSelection = (file: File) => {
    setErrorMessage(null);

    // Validate size limit (500KB)
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setErrorMessage(`File size (${(file.size / 1024).toFixed(1)} KB) exceeds maximum limit of 500 KB.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setUploadedFile({
        name: file.name,
        size: file.size,
        content: text,
      });
    };
    reader.onerror = () => {
      setErrorMessage("Failed to read the selected file.");
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelection(e.dataTransfer.files[0]);
    }
  };

  // Trigger scan execution
  const handleStartScan = async () => {
    setErrorMessage(null);

    let payloadContent = "";
    let sourceTypeToSend: "paste" | "repo" = "paste";

    if (activeTab === "paste") {
      if (!code.trim()) {
        setErrorMessage("Please enter or paste source code to review.");
        return;
      }
      payloadContent = code;
      sourceTypeToSend = "paste";
    } else if (activeTab === "upload") {
      if (!uploadedFile || !uploadedFile.content.trim()) {
        setErrorMessage("Please choose or drop a code file to upload.");
        return;
      }
      payloadContent = uploadedFile.content;
      sourceTypeToSend = "paste";
    } else if (activeTab === "repo") {
      if (!repoUrl.trim()) {
        setErrorMessage("Please enter a public GitHub repository URL (e.g. https://github.com/owner/repo).");
        return;
      }
      payloadContent = repoUrl.trim();
      sourceTypeToSend = "repo";
    }

    setScanStatus("submitting");
    setFindings([]);

    try {
      const res = await fetch(`${apiUrl}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          source_type: sourceTypeToSend,
          content: payloadContent,
          language: language,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Scan request failed with HTTP ${res.status}`);
      }

      const data = await res.json();
      setScanId(data.scan_id);
      setScanStatus("processing");
    } catch (err: any) {
      setScanStatus("error");
      setErrorMessage(err.message || "Failed to initiate security scan.");
    }
  };

  // Poll scan status every 2 seconds
  useEffect(() => {
    if (scanStatus !== "processing" || !scanId) {
      if (pollingRef.current) clearInterval(pollingRef.current);
      return;
    }

    const poll = async () => {
      try {
        const res = await fetch(`${apiUrl}/api/scan/${scanId}`);
        if (!res.ok) {
          throw new Error(`Failed to poll status (HTTP ${res.status})`);
        }
        const data: ScanResponse = await res.json();

        if (data.status === "done") {
          setFindings(data.findings || []);
          setScanStatus("done");
          if (pollingRef.current) clearInterval(pollingRef.current);
        } else if (data.status === "error") {
          setScanStatus("error");
          setErrorMessage("Scan processing failed on the backend.");
          if (pollingRef.current) clearInterval(pollingRef.current);
        }
      } catch (err: any) {
        console.error("Polling error:", err);
      }
    };

    pollingRef.current = setInterval(poll, 2000);
    poll();

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [scanStatus, scanId, apiUrl]);

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity.toUpperCase();
    if (s.includes("CRITICAL") || s.includes("BLOCKER")) {
      return {
        label: "CRITICAL",
        classes: "bg-red-950 text-red-300 border-red-700/80 font-bold shadow-sm shadow-red-950",
      };
    }
    if (s.includes("HIGH") || s.includes("ERROR")) {
      return {
        label: "HIGH",
        classes: "bg-orange-950 text-orange-300 border-orange-700/80 font-semibold shadow-sm shadow-orange-950",
      };
    }
    if (s.includes("MEDIUM") || s.includes("WARN")) {
      return {
        label: "MEDIUM",
        classes: "bg-yellow-950 text-yellow-300 border-yellow-700/80 font-medium shadow-sm shadow-yellow-950",
      };
    }
    return {
      label: "LOW",
      classes: "bg-blue-950 text-blue-300 border-blue-700/80 font-medium shadow-sm shadow-blue-950",
    };
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 selection:bg-indigo-500 selection:text-white pb-16">
      {/* Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/70 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3.5">
            <div className="p-2.5 bg-indigo-600/20 border border-indigo-500/40 rounded-xl shadow-inner">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-base sm:text-lg text-white tracking-tight">
                  SecureAI Review
                </h1>
                <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-indigo-950/80 text-indigo-300 border border-indigo-700/60">
                  Semgrep + Groq LLM
                </span>
              </div>
              <p className="text-[11px] text-slate-400">AST Static Analysis & AI Security Explanations</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-lg border border-slate-800 shadow-sm">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="hidden sm:inline text-slate-400">Backend:</span>
              <code className="text-slate-300 font-mono text-[11px]">{apiUrl}</code>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8 space-y-8">
        {/* Input Section Card */}
        <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-7 shadow-2xl backdrop-blur-sm space-y-6">
          {/* Top Bar: Tabs & Language Dropdown */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
            {/* 3 Parallel Tabs */}
            <div className="flex flex-wrap items-center gap-1.5 bg-slate-950 p-1.5 rounded-xl border border-slate-800/90">
              <button
                type="button"
                onClick={() => setActiveTab("paste")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all duration-150 ${
                  activeTab === "paste"
                    ? "bg-indigo-600 text-white shadow-md shadow-indigo-950 font-semibold"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                }`}
              >
                <Code2 className="w-4 h-4" />
                Paste Code
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("upload")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all duration-150 ${
                  activeTab === "upload"
                    ? "bg-indigo-600 text-white shadow-md shadow-indigo-950 font-semibold"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                }`}
              >
                <Upload className="w-4 h-4" />
                Upload File
                {uploadedFile && (
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("repo")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all duration-150 ${
                  activeTab === "repo"
                    ? "bg-indigo-600 text-white shadow-md shadow-indigo-950 font-semibold"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                }`}
              >
                <GitBranch className="w-4 h-4" />
                GitHub Repo URL
                {repoUrl.trim() && (
                  <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
                )}
              </button>
            </div>

            {/* Language Selector */}
            <div className="flex items-center space-x-2.5">
              <label htmlFor="language-select" className="text-xs font-medium text-slate-400">
                Language:
              </label>
              <select
                id="language-select"
                value={language}
                onChange={(e) => handleLanguageChange(e.target.value)}
                className="bg-slate-950 border border-slate-700 hover:border-slate-600 text-slate-200 text-xs sm:text-sm rounded-lg px-3.5 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-colors cursor-pointer"
              >
                <option value="python">Python (.py)</option>
                <option value="javascript">JavaScript (.js)</option>
                <option value="typescript">TypeScript (.ts)</option>
                <option value="java">Java (.java)</option>
              </select>
            </div>
          </div>

          {/* TAB 1: PASTE CODE */}
          {activeTab === "paste" && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                <span>Enter or paste code snippet to review for security vulnerabilities:</span>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={handleLoadSample}
                    className="text-indigo-400 hover:text-indigo-300 hover:underline flex items-center gap-1.5 font-medium transition-colors cursor-pointer"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    Load Insecure {LANGUAGE_LABELS[language] || "Python"} Sample
                  </button>

                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-slate-400 hover:text-rose-400 flex items-center gap-1 font-medium transition-colors cursor-pointer"
                    title="Clear editor and reset results"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    Clear / Reset
                  </button>
                </div>
              </div>

              <div className="relative rounded-xl border border-slate-800 bg-slate-950 focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 transition-all">
                <textarea
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  rows={13}
                  placeholder={`Paste your ${LANGUAGE_LABELS[language]} code here or click "Load Insecure ${LANGUAGE_LABELS[language]} Sample"...`}
                  className="w-full bg-transparent font-mono text-xs sm:text-sm text-slate-200 p-4 rounded-xl focus:outline-none resize-y"
                  spellCheck={false}
                />
              </div>
            </div>
          )}

          {/* TAB 2: UPLOAD FILE */}
          {activeTab === "upload" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Upload a single source code file ({LANGUAGE_EXTENSIONS[language]}):</span>
                {uploadedFile && (
                  <button
                    type="button"
                    onClick={handleReset}
                    className="text-slate-400 hover:text-rose-400 flex items-center gap-1 font-medium transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    Clear File
                  </button>
                )}
              </div>

              <input
                ref={fileInputRef}
                type="file"
                accept={LANGUAGE_EXTENSIONS[language]}
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleFileSelection(e.target.files[0]);
                  }
                }}
                className="hidden"
              />

              {!uploadedFile ? (
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-150 ${
                    isDragging
                      ? "border-indigo-500 bg-indigo-950/20"
                      : "border-slate-800 hover:border-slate-700 bg-slate-950/60 hover:bg-slate-950"
                  }`}
                >
                  <div className="inline-flex p-4 rounded-2xl bg-indigo-950/60 text-indigo-400 border border-indigo-800/40 mb-3">
                    <FileUp className="w-7 h-7" />
                  </div>
                  <h3 className="text-sm font-semibold text-slate-200">
                    Click to browse or drag and drop a file
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Accepts <strong className="text-slate-300">{LANGUAGE_EXTENSIONS[language]}</strong> files (Max 500 KB)
                  </p>
                </div>
              ) : (
                <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-3.5">
                    <div className="p-2.5 bg-emerald-950/60 border border-emerald-800/60 rounded-lg text-emerald-400">
                      <FileCode className="w-5 h-5" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-slate-100">{uploadedFile.name}</p>
                      <p className="text-xs text-slate-400">
                        {(uploadedFile.size / 1024).toFixed(2)} KB • {uploadedFile.content.split("\n").length} lines
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="text-xs px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors"
                    >
                      Change File
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setUploadedFile(null);
                        if (fileInputRef.current) fileInputRef.current.value = "";
                      }}
                      className="p-1.5 rounded-lg bg-slate-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-400 border border-slate-700 transition-colors"
                      title="Remove file"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: GITHUB REPO URL */}
          {activeTab === "repo" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Enter a public Git / GitHub repository to shallow-clone and scan:</span>
                {repoUrl && (
                  <button
                    type="button"
                    onClick={() => setRepoUrl("")}
                    className="text-slate-400 hover:text-rose-400 flex items-center gap-1 font-medium transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    Clear URL
                  </button>
                )}
              </div>

              <div className="relative rounded-xl border border-slate-800 bg-slate-950 focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 transition-all p-1">
                <div className="flex items-center px-3.5">
                  <GitBranch className="w-4 h-4 text-slate-500 mr-2.5" />
                  <input
                    type="url"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    className="w-full bg-transparent text-xs sm:text-sm text-slate-200 py-3 focus:outline-none font-mono"
                  />
                </div>
              </div>
              <p className="text-[11px] text-slate-500">
                The backend performs a shallow git clone (depth 1) in an isolated sandboxed directory, executes Semgrep across the entire repo, and cleans up immediately after.
              </p>
            </div>
          )}

          {/* Error display */}
          {errorMessage && (
            <div className="p-4 rounded-xl bg-red-950/60 border border-red-800/80 text-red-300 text-sm flex items-start gap-3 shadow-md">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-xs sm:text-sm">Scan Error</p>
                <p className="text-xs text-red-300/90 mt-0.5">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Bottom Action Row */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2 border-t border-slate-800/60">
            <p className="text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Credentials and tokens are masked before external AI explanation requests.</span>
            </p>

            <button
              type="button"
              onClick={handleStartScan}
              disabled={scanStatus === "submitting" || scanStatus === "processing"}
              className="w-full sm:w-auto px-7 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-600 text-white font-semibold text-xs sm:text-sm transition-all duration-150 shadow-lg shadow-indigo-950/60 flex items-center justify-center gap-2.5 cursor-pointer disabled:cursor-not-allowed active:scale-[0.98]"
            >
              {scanStatus === "processing" || scanStatus === "submitting" ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-indigo-300" />
                  Analyzing with Semgrep & Groq...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-indigo-300" />
                  Run Security Review
                </>
              )}
            </button>
          </div>
        </section>

        {/* Loading / Polling Banner */}
        {(scanStatus === "processing" || scanStatus === "submitting") && (
          <section className="bg-slate-900/90 border border-indigo-900/60 rounded-2xl p-8 sm:p-10 text-center space-y-4 shadow-xl">
            <div className="inline-flex p-3.5 rounded-full bg-indigo-950/80 border border-indigo-700/60 text-indigo-400 animate-pulse shadow-md">
              <RefreshCw className="w-8 h-8 animate-spin" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base sm:text-lg font-bold text-slate-100">
                Security Scan In Progress (Scan #{scanId || "..."})
              </h3>
              <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto">
                Executing Semgrep static analysis, masking sensitive tokens, and generating clear Groq Llama-3.3-70B AI explanations...
              </p>
            </div>
            <div className="flex justify-center items-center flex-wrap gap-4 sm:gap-8 text-xs text-slate-400 pt-3">
              <span className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                AST Rule Matching
              </span>
              <span className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                Secret Masking
              </span>
              <span className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />
                Plain-English Remediation
              </span>
            </div>
          </section>
        )}

        {/* Results Section */}
        {scanStatus === "done" && (
          <section className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2.5">
                  Scan Results
                  <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                    Scan ID: #{scanId}
                  </span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  {findings.length === 0
                    ? "No security vulnerabilities detected by static analysis rules."
                    : `Detected ${findings.length} security finding${findings.length === 1 ? "" : "s"}.`}
                </p>
              </div>

              <button
                type="button"
                onClick={handleReset}
                className="text-xs px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition-colors flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                New Scan
              </button>
            </div>

            {/* Zero Findings Clean State */}
            {findings.length === 0 && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-12 text-center space-y-3 shadow-lg">
                <div className="inline-flex p-3.5 rounded-full bg-emerald-950/80 border border-emerald-800/80 text-emerald-400 shadow-md">
                  <CheckCircle2 className="w-8 h-8" />
                </div>
                <h3 className="text-base font-bold text-slate-100">No Security Issues Found</h3>
                <p className="text-xs sm:text-sm text-slate-400 max-w-md mx-auto">
                  Semgrep static analysis rules did not flag any matching security vulnerabilities or insecure patterns.
                </p>
              </div>
            )}

            {/* Findings List */}
            <div className="space-y-6">
              {findings.map((finding, idx) => {
                const badge = getSeverityBadge(finding.severity);
                return (
                  <div
                    key={`${finding.rule_id}-${idx}`}
                    className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition-all rounded-2xl p-6 sm:p-7 shadow-xl space-y-5"
                  >
                    {/* Finding Header */}
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span className={`text-xs px-3 py-1 rounded-md border ${badge.classes}`}>
                          {badge.label}
                        </span>

                        {finding.source === "ai_only" ? (
                          <span className="text-xs px-2.5 py-1 rounded-md bg-purple-950/80 text-purple-300 border border-purple-700/80 font-semibold flex items-center gap-1.5 shadow-sm shadow-purple-950">
                            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                            AI Independent Review (Unconfirmed by Static Analysis)
                          </span>
                        ) : (
                          <span className="text-xs px-2.5 py-1 rounded-md bg-emerald-950/70 text-emerald-300 border border-emerald-700/70 font-medium flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            Semgrep AST Verified
                          </span>
                        )}

                        <code className="text-xs font-mono bg-slate-950 text-indigo-300 px-3 py-1 rounded-md border border-slate-800">
                          {finding.rule_id}
                        </code>
                        <span className="text-xs text-slate-400 flex items-center gap-1 font-mono bg-slate-950/60 px-2.5 py-1 rounded border border-slate-800/60">
                          <Terminal className="w-3.5 h-3.5 text-slate-500" />
                          {finding.file_path}:{finding.line_number}
                        </span>
                      </div>

                      {/* Severity Conflict Warning */}
                      {finding.severity_conflict && (
                        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-amber-950/80 text-amber-300 border border-amber-700/80 text-xs font-medium">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span>Severity Conflict: AI & Static Analyzer Disagreed (≥2 levels)</span>
                        </div>
                      )}
                    </div>

                    {/* Detection Summary Message */}
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        {finding.source === "ai_only" ? (
                          <>
                            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                            <span className="text-purple-300">AI Security Finding (Manual Audit Pass)</span>
                          </>
                        ) : (
                          <>
                            <Code2 className="w-3.5 h-3.5 text-slate-400" />
                            <span>Static Analysis Detection</span>
                          </>
                        )}
                      </h4>
                      <p className="text-xs sm:text-sm text-slate-200 bg-slate-950 p-3.5 rounded-xl border border-slate-800/90 font-mono leading-relaxed">
                        {finding.raw_message}
                      </p>
                    </div>

                    {/* AI Plain-English Explanation */}
                    {finding.ai_explanation && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                            AI Security Explanation (Groq Llama-3.3-70B)
                          </h4>
                          {finding.ai_confidence && (
                            <span className="text-[11px] text-slate-400">
                              Confidence: <strong className="text-slate-300 uppercase">{finding.ai_confidence}</strong>
                            </span>
                          )}
                        </div>
                        <div className="p-4 bg-indigo-950/20 border border-indigo-900/40 rounded-xl text-xs sm:text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                          {finding.ai_explanation}
                        </div>
                      </div>
                    )}

                    {/* AI Suggested Fix (Advisory - NOT auto-applied) */}
                    {finding.ai_fix_suggestion && (
                      <div className="space-y-2.5">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            Suggested Fix (Remediation)
                          </h4>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(finding.ai_fix_suggestion || "", idx)}
                            className="text-xs text-slate-300 hover:text-white flex items-center gap-1.5 bg-slate-950 px-3 py-1 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors"
                          >
                            {copiedIndex === idx ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                Copied
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                Copy Code
                              </>
                            )}
                          </button>
                        </div>

                        {/* Explicit Non-Auto-Apply Banner */}
                        <div className="relative rounded-xl overflow-hidden border border-emerald-900/60 bg-slate-950 shadow-inner">
                          <div className="bg-emerald-950/50 px-4 py-2 border-b border-emerald-900/50 flex items-center justify-between text-[11px] text-emerald-300">
                            <span className="font-semibold flex items-center gap-1.5">
                              ⚠️ AI-suggested — review before applying
                            </span>
                            <span className="text-emerald-400/80 italic hidden sm:inline">
                              Manual patch review required
                            </span>
                          </div>
                          <pre className="p-4 font-mono text-xs text-slate-200 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                            {finding.ai_fix_suggestion}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        )}
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 mt-20 py-8 bg-slate-900/40 text-center text-xs text-slate-500 space-y-1.5">
        <p className="font-medium text-slate-400">SecureAI Review — Hackathon MVP Edition</p>
        <p className="text-[11px] text-slate-600">
          Semgrep AST Engine • Groq LLM (llama-3.3-70b-versatile) • In-memory / MySQL Storage
        </p>
      </footer>
    </main>
  );
}
