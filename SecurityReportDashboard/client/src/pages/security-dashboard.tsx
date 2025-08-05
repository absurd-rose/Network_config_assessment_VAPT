import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { Sidebar } from "@/components/security/sidebar";
import { SummaryCards } from "@/components/security/summary-cards";
import { SeverityChart } from "@/components/security/severity-chart";
import { SecurityFindings } from "@/components/security/security-findings";
import { type SeverityLevel, type CVEReportData } from "@shared/schema";
import { queryClient } from "@/lib/queryClient";
import React from "react";

type SecurityDashboardProps = {
  reportData: any;
};

// Dashboard data interface for the transformed data
interface DashboardData {
  device: {
    id: number;
    name: string;
    ipAddress: string;
    os: string;
    lastScan: string;
    status: string;
  };
  report: {
    totalVulnerabilities: number;
    totalIssues: number;
    cvesFound: number;
    highSeverity: number;
    exploitable: number;
    summary: {
      severityBreakdown: {
        critical: number;
        high: number;
        medium: number;
        low: number;
      };
    };
  };
  findings: Array<{
    id: number;
    deviceId: number;
    timestamp: string;
    title: string;
    description: string;
    cveId: string;
    severity: string;
    recommendation: string;
    estimatedTime: string;
    requiresReboot: number;
    cvssScore: number;
    url: string;
  }>;
}

export default function SecurityDashboard({ reportData }: SecurityDashboardProps) {
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | "">("");

  if (!reportData) {
    return <div>No dashboard data available</div>;
  }

  const device_info = reportData.device_info || {};
  const report_data = reportData || {};


  function handleRefresh() {
}
  // Transform rawData to CVEReportData (if rawData exists)
  const cveReportData: CVEReportData | null = report_data
    ? {
        device_info: {
          agent_id: device_info.agent_id.toString(),
          device_name: device_info.device_name,
          ip: device_info.ip,
          os: device_info.os,
          last_seen: device_info.last_seen
        },
        os_details: {
          build: report_data.os_details.build,
          display_version: report_data.os_details.display_version, 
          major: report_data.os_details.major,
          minor: report_data.os_details.minor,
          name: report_data.os_details.name,
          version: report_data.os_details.version
        },
        summary: {
          software_analyzed: report_data.summary.software_analyzed,
          alerts_found: report_data.summary.alerts_found,
          syscheck_entries: report_data.summary.syscheck_entries,
          total_cves: report_data.summary.total_cves,
          severity_breakdown: {
            Critical: report_data.summary.severity_breakdown.Critical || 0,
            High: report_data.summary.severity_breakdown.High || 0,
            Medium: report_data.summary.severity_breakdown.Medium || 0,
            Low: report_data.summary.severity_breakdown.Low || 0
          }
        },
        findings: report_data.findings.map((finding: any) => ({
          timestamp: finding.timestamp,
          software: finding.software,
          cve_id: finding.cveId,
          cvss_score: finding.cvss_score,
          description: finding.description,
          risk_level: finding.risk_level.charAt(0).toUpperCase() + finding.risk_level.slice(1),
          url: finding.url,
          remediation: {
            summary: finding.remediation.summary,
            references: finding.remediation.references
          }
        }))
      }
    : null;

  // Transform CVE data for your dashboard components
  const dashboardData: DashboardData | null = cveReportData ? {
    device: {
      id: parseInt(cveReportData.device_info.agent_id),
      name: cveReportData.device_info.device_name,
      ipAddress: cveReportData.device_info.ip,
      os: cveReportData.device_info.os,
      lastScan: cveReportData.device_info.last_seen,
      status: "active"
    },
    report: {
      totalVulnerabilities: cveReportData.summary.total_cves,
      totalIssues: cveReportData.summary.alerts_found,
      cvesFound: cveReportData.summary.total_cves,
      highSeverity: cveReportData.summary.severity_breakdown.High,
      exploitable: 0,
      summary: {
        severityBreakdown: {
          critical: cveReportData.summary.severity_breakdown.Critical,
          high: cveReportData.summary.severity_breakdown.High,
          medium: cveReportData.summary.severity_breakdown.Medium,
          low: cveReportData.summary.severity_breakdown.Low
        }
      }
    },
    findings: cveReportData.findings.map((finding, index) => ({
      id: index + 1,
      deviceId: parseInt(cveReportData.device_info.agent_id),
      timestamp: finding.timestamp,
      title: finding.software,
      description: finding.description,
      cveId: finding.cve_id,
      severity: finding.risk_level.toLowerCase(),
      recommendation: finding.remediation.summary,
      estimatedTime: "30 minutes",
      requiresReboot: 0,
      cvssScore: finding.cvss_score,
      url: finding.url
    }))
  } : null;
  // Filter findings based on search and severity
  const filteredFindings = dashboardData?.findings.filter(finding => {
    const matchesSearch = !searchQuery || 
      finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.cveId?.toLowerCase().includes(searchQuery.toLowerCase());
      
    const matchesSeverity = !severityFilter || 
      finding.severity.toLowerCase() === severityFilter.toLowerCase();
      
    return matchesSearch && matchesSeverity;
  }) || [];


  const handleExportPDF = () => {
    if (!dashboardData || !filteredFindings) return;
    
    const { device, report } = dashboardData;
    const findings = filteredFindings;
    
    // Create HTML content for PDF
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Security Report - ${device.name}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          .header { background: #1e293b; color: white; padding: 20px; margin-bottom: 20px; }
          .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
          .card { border: 1px solid #ccc; padding: 15px; text-align: center; }
          .findings { margin-top: 20px; }
          table { width: 100%; border-collapse: collapse; }
          th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
          th { background: #f5f5f5; }
          .critical { color: #dc2626; }
          .high { color: #f59e0b; }
          .medium { color: #3b82f6; }
          .low { color: #10b981; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>Security Report</h1>
          <p>Device: ${device.name} (${device.ipAddress})</p>
          <p>Generated: ${new Date().toLocaleString()}</p>
        </div>
        
        <div class="summary">
          <div class="card">
            <h3>Total Vulnerabilities</h3>
            <p>${report.totalVulnerabilities}</p>
          </div>
          <div class="card">
            <h3>Critical</h3>
            <p class="critical">${report.summary?.severityBreakdown?.critical || 0}</p>
          </div>
          <div class="card">
            <h3>High</h3>
            <p class="high">${report.summary?.severityBreakdown?.high || 0}</p>
          </div>
          <div class="card">
            <h3>Medium</h3>
            <p class="medium">${report.summary?.severityBreakdown?.medium || 0}</p>
          </div>
        </div>
        
        <div class="findings">
          <h2>Security Findings</h2>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>CVE ID</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              ${findings.map((finding: any) => `
                <tr>
                  <td class="${finding.severity}">${finding.severity.toUpperCase()}</td>
                  <td>${finding.title}</td>
                  <td>${finding.cveId || 'N/A'}</td>
                  <td>${finding.description}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </body>
      </html>
    `;
    
    // Create blob and download
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${device.name.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportExcel = () => {
    if (!dashboardData || !filteredFindings) return;
    
    const { device, report } = dashboardData;
    const findings = filteredFindings;
    
    // Create CSV content
    const csvContent = [
      ['Security Report - ' + device.name],
      ['Generated:', new Date().toLocaleString()],
      ['Device:', device.name],
      ['IP Address:', device.ipAddress],
      ['Total Vulnerabilities:', report.totalVulnerabilities],
      [],
      ['Severity', 'Title', 'CVE ID', 'Description', 'Timestamp'],
      ...findings.map((finding: any) => [
        finding.severity.toUpperCase(),
        finding.title,
        finding.cveId || 'N/A',
        finding.description,
        new Date(finding.timestamp).toLocaleString()
      ])
    ].map(row => row.join(',')).join('\n');
    
    // Create blob and download
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${device.name.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const handleSeverityFilter = (severity: SeverityLevel | "") => {
    setSeverityFilter(severity);
  };

  const handleChartClick = (severity: string) => {
    const severityLevel = severity as SeverityLevel;
    setSeverityFilter(severityLevel);
  };

  if (!dashboardData) {
    return (
      <div className="min-h-screen dashboard-bg flex items-center justify-center">
        <div className="text-center">
          <p className="text-slate-400">No dashboard data available</p>
        </div>
      </div>
    );
  }

  const { device, report } = dashboardData;
  const severityBreakdown = report.summary?.severityBreakdown || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  const transformedDevice = {
  id: device.id,
  agentId: device.id.toString(), // or whatever represents agentId logically
  deviceName: device.name,
  ip: device.ipAddress,
  os: device.os,
  lastSeen: typeof device.lastScan === "string" ? new Date(device.lastScan) : device.lastScan,
  status: device.status,
};
const summaryReport = {
  id: device.id,
  deviceId: device.id,
  generatedAt: new Date(device.lastScan),
  softwareAnalyzed: report_data.summary?.software_analyzed ?? 0,
  alertsFound: report_data.summary?.alerts_found ?? 0,
  syscheckEntries: report_data.summary?.syscheck_entries ?? 0,
  totalCves: report_data.summary?.total_cves ?? 0,
  severityBreakdown: report_data.summary?.severity_breakdown ?? {},
  totalIssues: report_data.summary?.alerts_found ?? 0,
  cvesFound: report_data.summary?.total_cves ?? 0,
  highSeverity: report_data.summary?.severity_breakdown?.High ?? 0,
  exploitable: 0, 
};
  return (
    <div className="min-h-screen dashboard-bg">
      <div className="flex min-h-screen">
        <Sidebar
          device={transformedDevice}
          onRefresh={handleRefresh}
          onExportPDF={handleExportPDF}
          onExportExcel={handleExportExcel}
          autoRefresh={autoRefresh}
          onAutoRefreshChange={setAutoRefresh}
        />

        {/* Main Content */}
        <main className="flex-1 p-8 overflow-y-auto">
          {/* Header Section */}
          <div className="mb-8 animate-slide-up">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-white mb-2">Security Report</h1>
                <p className="text-slate-400">Comprehensive security analysis and vulnerability assessment</p>
              </div>
              <div className="flex items-center space-x-4">
                <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-2">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="text-red-500 h-4 w-4" />
                    <span className="text-red-500 font-semibold">Critical Risk</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Summary Metrics */}          
          <SummaryCards report={summaryReport} />

          {/* Charts Section */}
          <div className="mb-8">
            <SeverityChart data={severityBreakdown} onSeverityClick={handleChartClick} />
          </div>

          {/* Security Findings */}
          <SecurityFindings 
            findings={filteredFindings}
            onSearch={handleSearch}
            onSeverityFilter={handleSeverityFilter}
          />
        </main>
      </div>
    </div>
  );
}
