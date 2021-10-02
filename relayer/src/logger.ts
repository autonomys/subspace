import * as pino from "pino";

const logger = pino({ prettyPrint: true });

logger.level = process.env.DEBUG ? 'debug' : 'info';

export default logger;
