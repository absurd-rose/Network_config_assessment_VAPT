import { useState } from "react";
import { List, Search, Eye, MoreVertical, Clock, RefreshCw, ExternalLink } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { type SeverityLevel, severityLevels } from "@shared/schema";

// Updated interface for the dashboard findings format
interface SecurityFinding {
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
}

interface SecurityFindingsProps {
  findings: SecurityFinding[];
  onSearch: (query: string) => void;
  onSeverityFilter: (severity: SeverityLevel | "") => void;
}

export function SecurityFindings({ findings, onSearch, onSeverityFilter }: SecurityFindingsProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<SeverityLevel | "">("");

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    onSearch(value);
  };

  const handleSeverityChange = (value: string) => {
    const severity = value === "all" ? "" : (value as SeverityLevel);
    setSelectedSeverity(severity);
    onSeverityFilter(severity);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return "fas fa-exclamation-triangle";
      case "high":
        return "fas fa-exclamation-circle";
      case "medium":
        return "fas fa-info-circle";
      case "low":
        return "fas fa-check-circle";
      default:
        return "fas fa-info-circle";
    }
  };

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case "critical":
        return "severity-critical bg-red-500/10 border-red-500/20";
      case "high":
        return "severity-high bg-amber-500/10 border-amber-500/20";
      case "medium":
        return "severity-medium bg-blue-500/10 border-blue-500/20";
      case "low":
        return "severity-low bg-green-500/10 border-green-500/20";
      default:
        return "text-slate-400 bg-slate-500/10 border-slate-500/20";
    }
  };

  const formatTimestamp = (date: Date | string) => {
    const now = new Date();
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const diff = now.getTime() - dateObj.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) {
      return "Today, " + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (hours < 24) {
      return "Today, " + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
      return dateObj.toLocaleDateString() + ", " + dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
  };

  return (
    <div className="glassmorphism rounded-xl p-6 animate-slide-up">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white flex items-center">
          <List className="text-purple-500 mr-3" />
          Security Findings
        </h2>
        
        {/* Filters and Search */}
        <div className="flex items-center space-x-4">
          <div className="relative">
            <Input
              type="text"
              placeholder="Search findings..."
              value={searchQuery}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="bg-slate-700 text-white pl-10 pr-4 py-2 rounded-lg border-slate-600 focus:ring-purple-500 w-64"
            />
            <Search className="text-slate-400 absolute left-3 top-3 h-4 w-4" />
          </div>
          
          <Select value={selectedSeverity || "all"} onValueChange={handleSeverityChange}>
            <SelectTrigger className="bg-slate-700 text-white border-slate-600 focus:ring-purple-500 w-48">
              <SelectValue placeholder="All Severities" />
            </SelectTrigger>
            <SelectContent className="bg-slate-700 border-slate-600">
              <SelectItem value="all" className="text-white">All Severities</SelectItem>
              {severityLevels.map((level) => (
                <SelectItem key={level} value={level} className="text-white">
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">TIMESTAMP</th>
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">SOFTWARE/ISSUE</th>
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">CVE ID</th>
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">CVSS SCORE</th>
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">SEVERITY</th>
              <th className="text-left py-4 px-4 text-slate-400 font-medium text-sm">RECOMMENDATIONS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {findings.map((finding) => (
              <tr key={finding.id} className="hover:bg-slate-800/50 transition-colors">
                <td className="py-4 px-4">
                  <span className="text-slate-300 text-sm">{formatTimestamp(finding.timestamp)}</span>
                </td>
                <td className="py-4 px-4">
                  <div>
                    <p className="text-white font-medium">{finding.title}</p>
                    <p className="text-slate-400 text-sm mt-1">{finding.description}</p>
                  </div>
                </td>
                <td className="py-4 px-4">
                  {finding.cveId ? (
                    <a 
                      href={finding.url || `https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400 text-sm font-medium hover:bg-blue-500/20 transition-colors"
                    >
                      {finding.cveId}
                      <ExternalLink className="ml-2 h-3 w-3" />
                    </a>
                  ) : (
                    <span className="text-slate-500 text-sm">N/A</span>
                  )}
                </td>
                <td className="py-4 px-4">
                  {finding.cvssScore ? (
                    <div className="flex items-center">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-sm font-semibold ${
                        finding.cvssScore >= 9.0 ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                        finding.cvssScore >= 7.0 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                        finding.cvssScore >= 4.0 ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                        'bg-green-500/10 text-green-400 border border-green-500/20'
                      }`}>
                        {finding.cvssScore.toFixed(1)}
                      </span>
                    </div>
                  ) : (
                    <span className="text-slate-500 text-sm">N/A</span>
                  )}
                </td>
                <td className="py-4 px-4">
                  <span className={`inline-flex items-center px-3 py-1 border rounded-lg text-sm font-semibold ${getSeverityClass(finding.severity)}`}>
                    <i className={`${getSeverityIcon(finding.severity)} mr-2`}></i>
                    {finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)}
                  </span>
                </td>
                <td className="py-4 px-4">
                  <p className="text-slate-300 text-sm">{finding.recommendation}</p>
                  <div className="flex items-center mt-2">
                    <Clock className="text-blue-400 mr-1 h-3 w-3" />
                    <span className="text-blue-400 text-xs">Estimated time: {finding.estimatedTime}</span>
                    {finding.requiresReboot === 1 && (
                      <>
                        <RefreshCw className="text-purple-400 ml-2 mr-1 h-3 w-3" />
                        <span className="text-purple-400 text-xs">Requires reboot</span>
                      </>
                    )}
                  </div>
                </td>

              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-6 pt-6 border-t border-slate-700">
        <div className="flex items-center space-x-2">
          <span className="text-slate-400 text-sm">Showing</span>
          <Select defaultValue="5">
            <SelectTrigger className="bg-slate-700 text-white border-slate-600 w-16 h-8">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-slate-700 border-slate-600">
              <SelectItem value="5">5</SelectItem>
              <SelectItem value="10">10</SelectItem>
              <SelectItem value="25">25</SelectItem>
              <SelectItem value="50">50</SelectItem>
            </SelectContent>
          </Select>
          <span className="text-slate-400 text-sm">of {findings.length} results</span>
        </div>

        <div className="flex items-center space-x-2">
          <Button 
            size="sm" 
            variant="ghost"
            className="px-3 py-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
            disabled
          >
            &lt;
          </Button>
          <Button 
            size="sm"
            className="px-3 py-2 bg-purple-600 text-white rounded-lg font-medium"
          >
            1
          </Button>
          <Button 
            size="sm" 
            variant="ghost"
            className="px-3 py-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
          >
            2
          </Button>
          <Button 
            size="sm" 
            variant="ghost"
            className="px-3 py-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
          >
            3
          </Button>
          <span className="px-2 text-slate-400">...</span>
          <Button 
            size="sm" 
            variant="ghost"
            className="px-3 py-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
          >
            6
          </Button>
          <Button 
            size="sm" 
            variant="ghost"
            className="px-3 py-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
          >
            &gt;
          </Button>
        </div>
      </div>
    </div>
  );
}
