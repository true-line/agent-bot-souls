#!/usr/bin/env node
import { runSoulCli } from '../lib/soul-cli.mjs';

process.exitCode = await runSoulCli(process.argv.slice(2));
