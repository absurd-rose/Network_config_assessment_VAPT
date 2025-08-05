# Security Dashboard Application

## Overview

This is a full-stack security dashboard application built with a modern tech stack. The application provides a comprehensive view of security findings, vulnerabilities, and device monitoring capabilities. It features a React frontend with a Node.js/Express backend, using PostgreSQL for data persistence and a clean, professional UI built with shadcn/ui components.

## System Architecture

The application follows a monorepo structure with clear separation between client, server, and shared code:

- **Frontend**: React with TypeScript, using Vite as the build tool
- **Backend**: Express.js with TypeScript for API endpoints
- **Database**: PostgreSQL with Drizzle ORM for type-safe database operations
- **UI Framework**: shadcn/ui components with Radix UI primitives and Tailwind CSS
- **State Management**: TanStack Query for server state management

## Key Components

### Frontend Architecture
- **React Router**: Uses Wouter for lightweight client-side routing
- **UI Components**: shadcn/ui component library with consistent design system
- **Styling**: Tailwind CSS with custom CSS variables for theming
- **Charts**: Chart.js integration for data visualization
- **State Management**: TanStack Query for API data fetching and caching

### Backend Architecture
- **Express Server**: RESTful API with middleware for logging and error handling
- **Database Layer**: Drizzle ORM with PostgreSQL for type-safe database operations
- **Storage Abstraction**: Interface-based storage layer supporting both memory and database implementations
- **Route Organization**: Centralized route registration with proper error handling

### Database Schema
The application uses three main entities:
- **Devices**: Store device information including name, IP address, OS, and scan status
- **Security Findings**: Store vulnerability details with severity levels, CVE IDs, and remediation info
- **Security Reports**: Store aggregated security report data with metrics and summaries

## Data Flow

1. **Client Requests**: Frontend makes API calls using TanStack Query
2. **API Processing**: Express routes handle requests and interact with storage layer
3. **Data Persistence**: Storage layer abstracts database operations using Drizzle ORM
4. **Response Handling**: API responses are cached and managed by TanStack Query
5. **UI Updates**: React components automatically re-render based on query state changes

## External Dependencies

### Core Dependencies
- **@neondatabase/serverless**: PostgreSQL database connection for Neon
- **drizzle-orm**: Type-safe ORM for database operations
- **@tanstack/react-query**: Server state management
- **@radix-ui/***: Accessible UI primitives
- **chart.js**: Data visualization for security metrics
- **wouter**: Lightweight React router

### Development Tools
- **Vite**: Fast build tool and development server
- **TypeScript**: Type safety across the entire application
- **Tailwind CSS**: Utility-first CSS framework
- **drizzle-kit**: Database migration and schema management

## Deployment Strategy

The application is configured for modern deployment platforms:

- **Build Process**: Vite builds the client, esbuild bundles the server
- **Database**: Uses environment variable `DATABASE_URL` for connection
- **Static Assets**: Served from `dist/public` after build
- **Development**: Hot reload with Vite dev server and TSX for server
- **Production**: Single Node.js process serving both API and static files

The build strategy separates client and server builds, with the server bundled as ESM modules and static assets served from the Express server in production.

## Changelog

Changelog:
- June 27, 2025. Initial setup
- June 27, 2025. Completed V2 security dashboard implementation with vulnerability trends section removed
- June 27, 2025. Updated auto-refresh timing to 5 minutes per user request
- June 27, 2025. Implemented interactive pie chart with click-to-filter functionality and removed non-functional buttons
- June 27, 2025. Added PDF (HTML) and Excel (CSV) export functionality for security reports
- June 27, 2025. Removed actions column from security findings table per user request

## User Preferences

Preferred communication style: Simple, everyday language.