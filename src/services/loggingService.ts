import { LogType, SIEMLog } from '../types';

class LoggingService {
  async log(type: LogType, source: string, details: any, metadata?: Record<string, any>) {
    try {
      const response = await fetch('/api/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type,
          source,
          details,
          metadata,
        }),
      });
      return await response.json();
    } catch (error) {
      console.error('Failed to log to server:', error);
      // Fallback to local console if server logging fails
      console.warn('Logging fallback:', { type, source, details, metadata });
    }
  }

  async getLogs(): Promise<SIEMLog[]> {
    try {
      const response = await fetch('/api/logs');
      return await response.json();
    } catch (error) {
      console.error('Failed to fetch logs:', error);
      return [];
    }
  }

  /**
   * Specifically logs data transformations (Phase 2 normalization)
   */
  async logTransformation(source: string, input: any, output: any, logic?: string) {
    return this.log(LogType.NORMALIZATION, source, {
      input,
      output,
      logic: logic || 'Data structure transformation'
    });
  }

  /**
   * Specifically logs API interactions (Phase 1 ingestion)
   */
  async logApiInteraction(endpoint: string, request: any, response: any, method: string = 'POST') {
    await this.log(LogType.INGESTION, endpoint, { method, payload: request });
    await this.log(LogType.INGESTION, endpoint, { status: 'success', data: response });
  }
}

export const loggingService = new LoggingService();
