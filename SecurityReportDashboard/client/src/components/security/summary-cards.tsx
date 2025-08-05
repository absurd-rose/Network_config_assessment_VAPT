import { Bug, Shield, AlertTriangle, Crosshair } from "lucide-react";
import { type SecurityReport } from "@shared/schema";

interface SummaryCardsProps {
  report: SecurityReport;
}

export function SummaryCards({ report }: SummaryCardsProps) {
  console.log(report)
  const cards = [
    {
      title: "Total Issues",
      value: report.totalIssues,
      icon: Bug,
      color: "blue",
      change: "+3",
      changeType: "increase" as const,
      progress: 68
    },
    {
      title: "CVEs Found", 
      value: report.cvesFound,
      icon: Shield,
      color: "red",
      change: "5 new",
      changeType: "increase" as const,
      progress: 76
    },
    {
      title: "High Severity",
      value: report.highSeverity,
      icon: AlertTriangle,
      color: "amber",
      change: "+2 critical",
      changeType: "increase" as const,
      progress: 32
    },
    {
      title: "Exploitable",
      value: report.exploitable,
      icon: Crosshair,
      color: "purple",
      change: "public exploits",
      changeType: "warning" as const,
      progress: 16
    }
  ];

  const getIconColorClass = (color: string) => {
    switch (color) {
      case "blue": return "text-blue-400";
      case "red": return "text-red-400";
      case "amber": return "text-amber-400";
      case "purple": return "text-purple-400";
      default: return "text-blue-400";
    }
  };

  const getProgressColorClass = (color: string) => {
    switch (color) {
      case "blue": return "from-blue-500 to-blue-400";
      case "red": return "from-red-500 to-red-400";
      case "amber": return "from-amber-500 to-amber-400";
      case "purple": return "from-purple-500 to-purple-400";
      default: return "from-blue-500 to-blue-400";
    }
  };

  const getChangeColorClass = (changeType: string) => {
    switch (changeType) {
      case "increase": return "text-red-400";
      case "warning": return "text-amber-400";
      default: return "text-red-400";
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8 animate-slide-up">
      {cards.map((card, index) => (
        <div key={index} className="gradient-border card-hover">
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <div className={`p-3 bg-${card.color}-500/10 rounded-xl`}>
                <card.icon className={`${getIconColorClass(card.color)} text-xl h-6 w-6`} />
              </div>
              <div className="text-right">
                <p className="text-slate-400 text-sm font-medium">
                  {index === 0 && "vs last scan"}
                  {index === 1 && "new found"}
                  {index === 2 && "critical since"}
                  {index === 3 && "public exploits"}
                </p>
                <p className={`text-sm font-semibold ${getChangeColorClass(card.changeType)}`}>
                  {card.change}
                </p>
              </div>
            </div>
            <h3 className="text-slate-400 text-sm font-medium mb-1">{card.title}</h3>
            <p className="text-3xl font-bold text-white">{card.value}</p>
            <div className="mt-3 bg-slate-700 rounded-full h-2">
              <div 
                className={`bg-gradient-to-r ${getProgressColorClass(card.color)} h-2 rounded-full`}
                style={{ width: `${card.progress}%` }}
              ></div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
