<<<<<<< HEAD
# Network_config_frontend
=======
# Security Dashboard

A modern, interactive security vulnerability dashboard built with React, TypeScript, and Express.

## Features

- 🔍 Interactive pie chart with click-to-filter functionality
- 📊 Real-time security metrics and severity breakdown
- 🔎 Advanced search and filtering for security findings
- 📱 Responsive design optimized for desktop use
- 📄 Export capabilities (HTML reports and CSV data)
- ⚡ Auto-refresh functionality (5-minute intervals)
- 🎨 Modern glassmorphism UI with professional styling

## Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

1. **Clone/Download the project**
   ```bash
   # If downloading, extract to your desired folder
   cd security-dashboard
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   ```

4. **Open your browser**
   ```
   http://localhost:5000
   ```

The application will automatically start both the backend API server and frontend development server.

## Project Structure

```
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/          # Page components
│   │   └── lib/            # Utilities and configuration
├── server/                 # Express backend
│   ├── index.ts           # Server entry point
│   ├── routes.ts          # API routes
│   └── storage.ts         # Data storage layer
├── shared/                # Shared TypeScript types
└── INTEGRATION_GUIDE.md   # Backend integration instructions
```

## API Integration

The dashboard is designed to work with any backend that provides JSON responses. Current endpoints:

- `GET /api/dashboard/:deviceId` - Device info and security summary
- `GET /api/findings/:deviceId` - Security findings with optional filtering

See `INTEGRATION_GUIDE.md` for detailed backend integration instructions.

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build

## Technology Stack

- **Frontend**: React 18, TypeScript, Vite, TailwindCSS
- **Backend**: Express.js, TypeScript
- **UI Components**: Radix UI, shadcn/ui
- **Charts**: Chart.js with React integration
- **State Management**: TanStack Query
- **Database**: Drizzle ORM (configurable for any SQL database)

## Features Overview

### Interactive Pie Chart
- Click segments to filter security findings
- Visual severity breakdown with color coding
- Hover effects and tooltips

### Security Findings Table
- Search by title, description, or timestamp
- Filter by severity level (Critical, High, Medium, Low)
- Clickable CVE links to external databases
- Estimated fix times and reboot requirements

### Export Functionality
- **PDF Export**: Downloads formatted HTML report (use browser Print → PDF)
- **Excel Export**: Downloads CSV file compatible with Excel/Google Sheets

### Auto-Refresh
- Configurable auto-refresh (currently 5 minutes)
- Manual refresh capability
- Real-time data updates

## Production Deployment

For production deployment, see `INTEGRATION_GUIDE.md` for:
- Database setup and migration
- Authentication implementation
- Environment configuration
- API integration with real security scanners

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

This project is designed for enterprise security monitoring and reporting.
>>>>>>> 5378312 (project upload)
