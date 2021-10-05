import * as pino from "pino";

const logger = pino({ 
    prettyPrint: true, 
    // remove PID and Hostname from logs from now
    formatters: { 
        bindings: () => ({}) 
    } 
});

logger.level = process.env.DEBUG ? 'debug' : 'info';

export default logger;
