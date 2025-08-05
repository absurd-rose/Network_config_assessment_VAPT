import { useEffect, useRef } from "react";
import { PieChart } from "lucide-react";
import {
  Chart as ChartJS,
  ArcElement,
  DoughnutController,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  ArcElement,
  DoughnutController,
  Tooltip,
  Legend
);

interface SeverityChartProps {
  data: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  onSeverityClick?: (severity: string) => void;
}

export function SeverityChart({ data, onSeverityClick }: SeverityChartProps) {
  const chartRef = useRef<HTMLCanvasElement>(null);
  const chartInstanceRef = useRef<ChartJS | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    // Destroy existing chart
    if (chartInstanceRef.current) {
      chartInstanceRef.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    if (!ctx) return;

    const severityLabels = ['Critical', 'High', 'Medium', 'Low'];
    const severityValues = [data.critical, data.high, data.medium, data.low];

    chartInstanceRef.current = new ChartJS(ctx, {
      type: 'doughnut',
      data: {
        labels: severityLabels,
        datasets: [{
          data: severityValues,
          backgroundColor: [
            'rgba(220, 38, 38, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(59, 130, 246, 0.8)',
            'rgba(16, 185, 129, 0.8)'
          ],
          borderColor: [
            'rgba(220, 38, 38, 1)',
            'rgba(245, 158, 11, 1)',
            'rgba(59, 130, 246, 1)',
            'rgba(16, 185, 129, 1)'
          ],
          borderWidth: 2,
          hoverBackgroundColor: [
            'rgba(220, 38, 38, 1)',
            'rgba(245, 158, 11, 1)',
            'rgba(59, 130, 246, 1)',
            'rgba(16, 185, 129, 1)'
          ],
          hoverBorderWidth: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '60%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#f8fafc',
              padding: 20,
              usePointStyle: true,
              pointStyle: 'circle',
              font: {
                size: 14
              }
            }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            titleColor: '#f8fafc',
            bodyColor: '#f8fafc',
            borderColor: 'rgba(148, 163, 184, 0.2)',
            borderWidth: 1,
            callbacks: {
              label: function(context) {
                const total = severityValues.reduce((a, b) => a + b, 0);
                const percentage = ((context.parsed / total) * 100).toFixed(1);
                return `${context.label}: ${context.parsed} (${percentage}%)`;
              }
            }
          }
        },
        onClick: (event, elements) => {
          if (elements.length > 0 && onSeverityClick) {
            const index = elements[0].index;
            const severity = severityLabels[index].toLowerCase();
            onSeverityClick(severity);
          }
        },
        onHover: (event, elements) => {
          if (chartRef.current) {
            chartRef.current.style.cursor = elements.length > 0 ? 'pointer' : 'default';
          }
        }
      }
    });

    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy();
      }
    };
  }, [data, onSeverityClick]);

  const totalVulnerabilities = data.critical + data.high + data.medium + data.low;
  const riskScore = ((data.critical * 4 + data.high * 3 + data.medium * 2 + data.low * 1) / (totalVulnerabilities * 4) * 10).toFixed(1);

  return (
    <div className="glassmorphism rounded-xl p-6 card-hover animate-slide-up">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-white flex items-center">
          <PieChart className="text-purple-500 mr-3" />
          Severity Breakdown
        </h2>
      </div>
      
      <div className="h-80">
        <canvas ref={chartRef}></canvas>
      </div>
      
      <div className="mt-6 grid grid-cols-2 gap-4">
        <div className="text-center">
          <p className="text-slate-400 text-sm font-medium">Total Vulnerabilities</p>
          <p className="text-2xl font-bold text-white">{totalVulnerabilities}</p>
        </div>
        <div className="text-center">
          <p className="text-slate-400 text-sm font-medium">Risk Score</p>
          <p className="text-2xl font-bold text-red-400">{riskScore}/10</p>
        </div>
      </div>
    </div>
  );
}
