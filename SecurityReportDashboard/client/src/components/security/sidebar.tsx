import { Shield, Server, FolderSync, FileText, FileSpreadsheet } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { type Device } from "@shared/schema";

interface SidebarProps {
  device: Device;
  onRefresh: () => void;
  onExportPDF: () => void;
  onExportExcel: () => void;
  autoRefresh: boolean;
  onAutoRefreshChange: (enabled: boolean) => void;
}

export function Sidebar({ 
  device, 
  onRefresh, 
  onExportPDF, 
  onExportExcel, 
  autoRefresh, 
  onAutoRefreshChange 
}: SidebarProps) {
  const formatLastScan = (date: Date | string) => {
    const now = new Date();
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const diff = now.getTime() - dateObj.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    
    if (hours < 1) {
      const minutes = Math.floor(diff / (1000 * 60));
      return `${minutes} minutes ago`;
    } else if (hours < 24) {
      return `${hours} hours ago`;
    } else {
      return dateObj.toLocaleDateString();
    }
  };

  return (
    <aside className="w-80 dashboard-sidebar border-r p-6 animate-fade-in">
      {/* Logo Section */}
      <div className="mb-8">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-cyan-500 rounded-xl flex items-center justify-center">
            <Shield className="text-white text-lg" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Security Dashboard</h1>
            <p className="text-slate-400 text-sm">Report Generation</p>
          </div>
        </div>
      </div>

      {/* Device Information Panel */}
      <div className="glassmorphism rounded-xl p-6 mb-6 card-hover">
        <h2 className="text-lg font-semibold mb-4 flex items-center text-white">
          <Server className="text-purple-500 mr-2" />
          Device Information
        </h2>
        
        <div className="space-y-4">
          <div>
            <label className="text-slate-400 text-sm font-medium">Device Name</label>
            <p className="text-white font-medium">{device.deviceName}</p>
          </div>
          
          <div>
            <label className="text-slate-400 text-sm font-medium">IP Address</label>
            <p className="text-white font-medium font-mono">{device.ip}</p>
          </div>
          
          <div>
            <label className="text-slate-400 text-sm font-medium">Last Scan</label>
            <p className="text-white font-medium">{formatLastScan(device.lastSeen)}</p>
          </div>
          
          <div>
            <label className="text-slate-400 text-sm font-medium">Operating System</label>
            <p className="text-white font-medium">{device.os}</p>
          </div>
        </div>
        
        <div className="mt-4 pt-4 border-t border-slate-700">
          <div className="flex items-center justify-between">
            <span className="text-slate-400 text-sm">Scan Status</span>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse-slow"></div>
              <span className="text-green-400 text-sm font-medium capitalize">{device.status}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="space-y-3">
        <Button 
          onClick={onRefresh}
          className="w-full bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white py-3 px-4 rounded-xl font-medium transition-all duration-200"
        >
          <FolderSync className="mr-2 h-4 w-4" />
          Refresh Data
        </Button>
        
        <div className="grid grid-cols-2 gap-3">
          <Button 
            onClick={onExportPDF}
            variant="secondary"
            className="bg-slate-700 hover:bg-slate-600 text-white py-3 px-4 rounded-xl font-medium transition-all duration-200"
          >
            <FileText className="mr-2 h-4 w-4" />
            PDF
          </Button>
          <Button 
            onClick={onExportExcel}
            variant="secondary"
            className="bg-slate-700 hover:bg-slate-600 text-white py-3 px-4 rounded-xl font-medium transition-all duration-200"
          >
            <FileSpreadsheet className="mr-2 h-4 w-4" />
            Excel
          </Button>
        </div>
      </div>

      {/* Auto-refresh Toggle */}
      <div className="mt-6 p-4 bg-slate-700/50 rounded-xl">
        <div className="flex items-center justify-between">
          <span className="text-slate-300 text-sm font-medium">Auto-refresh</span>
          <Switch 
            checked={autoRefresh}
            onCheckedChange={onAutoRefreshChange}
          />
        </div>
        <p className="text-slate-400 text-xs mt-1">Every 5 minutes</p>
      </div>
    </aside>
  );
}
