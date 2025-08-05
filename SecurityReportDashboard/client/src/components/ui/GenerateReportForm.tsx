import React, { useState } from "react";
import SecurityDashboard from '../../pages/security-dashboard';

// type GenerateReportFormProps = {
//   onSubmitAgentId: (agentId: string) => void;
// };

export type GenerateReportFormProps = {
  onReportData: (data: any) => void; 
};

export function GenerateReportForm({ onReportData }: GenerateReportFormProps) {
  const [agentId, setAgentId] = useState("");
  const [reportData, setReportData] = useState<any>(null);
  const [error, setError] = useState("");

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setAgentId(e.target.value);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setReportData(null);
    if (!agentId) {
      setError("Please enter a valid agent ID");
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:5001/generate-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: agentId }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || "Failed to generate report");
      }

      const data = await response.json();
      console.log(data)
      setReportData(data);
      onReportData(data);
    } catch (err: any) {
      setError(err.message || "Error occurred");
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <label htmlFor="agentId">Agent ID: </label>
        <input
          type="number"
          id="agentId"
          value={agentId}
          onChange={handleInputChange}
          placeholder="Enter agent ID"
          required
        />
        <button type="submit">Generate Report</button>
      </form>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {/* Only display the dashboard if data is available */}
      {reportData && <SecurityDashboard reportData={reportData} />}
    </div>
  );
}
