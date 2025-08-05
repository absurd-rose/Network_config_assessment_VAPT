import type { Express } from "express";
import { createServer, type Server } from "http";
import fetch from 'node-fetch';
import { storage } from "./storage";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  // Get dashboard data for a specific device
  app.get("/api/dashboard/:deviceId", async (req, res) => {
    try {
      const deviceId = parseInt(req.params.deviceId);
      if (isNaN(deviceId)) {
        return res.status(400).json({ message: "Invalid device ID" });
      }

      const data = await storage.getDashboardData(deviceId);
      res.json(data);
    } catch (error) {
      res.status(404).json({ message: error instanceof Error ? error.message : "Device not found" });
    }
  });

  // Get security findings with optional filtering
  app.get("/api/findings/:deviceId", async (req, res) => {
    try {
      const deviceId = parseInt(req.params.deviceId);
      if (isNaN(deviceId)) {
        return res.status(400).json({ message: "Invalid device ID" });
      }

      const { severity, search } = req.query;
      const findings = await storage.getSecurityFindings(
        deviceId,
        severity as any,
        search as string
      );
      
      res.json(findings);
    } catch (error) {
      res.status(500).json({ message: error instanceof Error ? error.message : "Internal server error" });
    }
  });

  // Refresh security data (simulates a new scan)
  app.post("/api/refresh/:deviceId", async (req, res) => {
    try {
      const deviceId = parseInt(req.params.deviceId);
      if (isNaN(deviceId)) {
        return res.status(400).json({ message: "Invalid device ID" });
      }

      // Update last scan time
      const device = await storage.getDevice(deviceId);
      if (!device) {
        return res.status(404).json({ message: "Device not found" });
      }

      // In a real implementation, this would trigger a new security scan
      // For now, we'll just update the timestamp and return fresh data
      // device.lastScan = new Date();
      
      const data = await storage.getDashboardData(deviceId);
      res.json(data);
    } catch (error) {
      res.status(500).json({ message: error instanceof Error ? error.message : "Internal server error" });
    }
  });

  // changes

app.post("/api/generate-report", async (req, res) => {
  try {
    const { agentId } = req.body;
    if (!agentId) {
      return res.status(400).json({ message: "Missing agentId in request body" });
    }

    const response = await fetch("http://127.0.0.1:5001/generate-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agentId }),
    });

    if (!response.ok) {
      const text = await response.text();
      return res.status(response.status).json({ message: text });
    }

    const report = await response.json();
    res.json(report);
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : "Internal server error" });
  }
});


  const httpServer = createServer(app);
  return httpServer;
}
