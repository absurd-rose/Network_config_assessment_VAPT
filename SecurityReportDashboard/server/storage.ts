import { 
  devices, 
  securityFindings, 
  securityReports,
  type Device, 
  type InsertDevice,
  type SecurityFinding,
  type InsertSecurityFinding,
  type SecurityReport,
  type InsertSecurityReport,
  type SeverityLevel
} from "@shared/schema";

export interface IStorage {
  // Device methods
  getDevice(id: number): Promise<Device | undefined>;
  createDevice(device: InsertDevice): Promise<Device>;
  
  // Security findings methods
  getSecurityFindings(deviceId: number, severity?: SeverityLevel, search?: string): Promise<SecurityFinding[]>;
  createSecurityFinding(finding: InsertSecurityFinding): Promise<SecurityFinding>;
  
  // Security report methods
  getLatestSecurityReport(deviceId: number): Promise<SecurityReport | undefined>;
  createSecurityReport(report: InsertSecurityReport): Promise<SecurityReport>;
  
  // Dashboard data
  getDashboardData(deviceId: number): Promise<{
    device: Device;
    report: SecurityReport;
    findings: SecurityFinding[];
  }>;
}

export class MemStorage implements IStorage {
  private devices: Map<number, Device>;
  private securityFindings: Map<number, SecurityFinding>;
  private securityReports: Map<number, SecurityReport>;
  private currentDeviceId: number;
  private currentFindingId: number;
  private currentReportId: number;

  constructor() {
    this.devices = new Map();
    this.securityFindings = new Map();
    this.securityReports = new Map();
    this.currentDeviceId = 1;
    this.currentFindingId = 1;
    this.currentReportId = 1;
    this.initializeMockData();
  }

  private initializeMockData() {
    // Create a sample device
    const device: Device = {
      id: 1,
      name: "Web Server #1 (Production)",
      ipAddress: "192.168.1.45",
      os: "Ubuntu 20.04 LTS",
      lastScan: new Date(),
      status: "active"
    };
    this.devices.set(1, device);

    // Create sample security findings
    const findings: SecurityFinding[] = [
      {
        id: 1,
        deviceId: 1,
        timestamp: new Date(),
        title: "Apache Log4j Remote Code Execution",
        description: "Vulnerability in Apache Log4j allows attackers to execute arbitrary code",
        cveId: "CVE-2021-44228",
        severity: "critical",
        recommendation: "Update Apache Log4j to version 2.17.1 or later",
        estimatedTime: "30 minutes",
        requiresReboot: 0
      },
      {
        id: 2,
        deviceId: 1,
        timestamp: new Date(),
        title: "OpenSSL Buffer Overflow",
        description: "Buffer overflow in OpenSSL could lead to remote code execution",
        cveId: "CVE-2022-3786",
        severity: "high",
        recommendation: "Upgrade OpenSSL to version 3.0.7",
        estimatedTime: "45 minutes",
        requiresReboot: 0
      },
      {
        id: 3,
        deviceId: 1,
        timestamp: new Date(),
        title: "Linux Kernel Privilege Escalation",
        description: "Flaw in Linux kernel could allow local privilege escalation",
        cveId: "CVE-2021-4034",
        severity: "high",
        recommendation: "Apply Linux kernel security patches",
        estimatedTime: "1 hour",
        requiresReboot: 1
      },
      {
        id: 4,
        deviceId: 1,
        timestamp: new Date(),
        title: "Nginx HTTP Request Smuggling",
        description: "HTTP request smuggling vulnerability in Nginx",
        cveId: "CVE-2022-41741",
        severity: "medium",
        recommendation: "Update Nginx configuration and version",
        estimatedTime: "20 minutes",
        requiresReboot: 0
      },
      {
        id: 5,
        deviceId: 1,
        timestamp: new Date(),
        title: "Bash Information Disclosure",
        description: "Bash could allow local users to gain sensitive information",
        cveId: "CVE-2019-18276",
        severity: "low",
        recommendation: "Update Bash to latest version",
        estimatedTime: "15 minutes",
        requiresReboot: 0
      }
    ];

    findings.forEach(finding => {
      this.securityFindings.set(finding.id, finding);
    });

    // Create sample security report
    const report: SecurityReport = {
      id: 1,
      deviceId: 1,
      generatedAt: new Date(),
      totalIssues: 27,
      cvesFound: 19,
      highSeverity: 8,
      exploitable: 4,
      summary: {
        severityBreakdown: {
          critical: 4,
          high: 8,
          medium: 11,
          low: 4
        }
      }
    };
    this.securityReports.set(1, report);

    this.currentDeviceId = 2;
    this.currentFindingId = 6;
    this.currentReportId = 2;
  }

  async getDevice(id: number): Promise<Device | undefined> {
    return this.devices.get(id);
  }

  async createDevice(insertDevice: InsertDevice): Promise<Device> {
    const id = this.currentDeviceId++;
    const device: Device = { ...insertDevice, id, status: insertDevice.status || "active" };
    this.devices.set(id, device);
    return device;
  }

  async getSecurityFindings(deviceId: number, severity?: SeverityLevel, search?: string): Promise<SecurityFinding[]> {
    let findings = Array.from(this.securityFindings.values()).filter(
      finding => finding.deviceId === deviceId
    );

    if (severity) {
      findings = findings.filter(finding => finding.severity === severity);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      findings = findings.filter(finding => 
        finding.title.toLowerCase().includes(searchLower) ||
        finding.description.toLowerCase().includes(searchLower) ||
        (finding.cveId && finding.cveId.toLowerCase().includes(searchLower))
      );
    }

    return findings.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async createSecurityFinding(insertFinding: InsertSecurityFinding): Promise<SecurityFinding> {
    const id = this.currentFindingId++;
    const finding: SecurityFinding = { 
      ...insertFinding, 
      id,
      cveId: insertFinding.cveId || null,
      estimatedTime: insertFinding.estimatedTime || null,
      requiresReboot: insertFinding.requiresReboot || null
    };
    this.securityFindings.set(id, finding);
    return finding;
  }

  async getLatestSecurityReport(deviceId: number): Promise<SecurityReport | undefined> {
    return Array.from(this.securityReports.values())
      .filter(report => report.deviceId === deviceId)
      .sort((a, b) => b.generatedAt.getTime() - a.generatedAt.getTime())[0];
  }

  async createSecurityReport(insertReport: InsertSecurityReport): Promise<SecurityReport> {
    const id = this.currentReportId++;
    const report: SecurityReport = { 
      ...insertReport, 
      id,
      summary: insertReport.summary || {}
    };
    this.securityReports.set(id, report);
    return report;
  }

  async getDashboardData(deviceId: number): Promise<{
    device: Device;
    report: SecurityReport;
    findings: SecurityFinding[];
  }> {
    const device = await this.getDevice(deviceId);
    if (!device) {
      throw new Error(`Device with id ${deviceId} not found`);
    }

    const report = await this.getLatestSecurityReport(deviceId);
    if (!report) {
      throw new Error(`No security report found for device ${deviceId}`);
    }

    const findings = await this.getSecurityFindings(deviceId);

    return { device, report, findings };
  }
}

export const storage = new MemStorage();
