#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const YAML = require('yaml');

const rootDir = path.resolve(__dirname, '..');

function printHelp() {
  console.log(`Usage:
  node Tools/process-config.js <input.yaml|-> [output.yaml|-] [options]

Options:
  --script <path>              Override script path. Default: Script/mihomoScript.js
  -h, --help                   Show this help

Examples:
  node Tools/process-config.js input.yaml output.yaml
  npm run process-config -- input.yaml output.yaml
`);
}

function takeValue(args, index, optionName) {
  const value = args[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${optionName} requires a value`);
  }
  return value;
}

function parseArgs(argv) {
  const options = {
    inputPath: null,
    outputPath: null,
    scriptPath: path.join(rootDir, 'Script', 'mihomoScript.js'),
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    }

    if (arg === '--script') {
      options.scriptPath = takeValue(argv, i, '--script');
      i += 1;
      continue;
    }

    if (arg.startsWith('--script=')) {
      options.scriptPath = arg.slice('--script='.length);
      continue;
    }

    if (arg.startsWith('--')) {
      throw new Error(`Unknown option: ${arg}`);
    }

    if (!options.inputPath) {
      options.inputPath = arg;
      continue;
    }

    if (!options.outputPath) {
      options.outputPath = arg;
      continue;
    }

    throw new Error(`Unexpected argument: ${arg}`);
  }

  if (!options.inputPath) {
    throw new Error('Input YAML path is required');
  }

  options.scriptPath = path.resolve(rootDir, options.scriptPath);
  return options;
}

function readInput(inputPath) {
  if (inputPath === '-') {
    return fs.readFileSync(0, 'utf8');
  }

  return fs.readFileSync(path.resolve(rootDir, inputPath), 'utf8');
}

function writeOutput(outputPath, output) {
  if (!outputPath || outputPath === '-') {
    process.stdout.write(output);
    return;
  }

  const resolvedOutputPath = path.resolve(rootDir, outputPath);
  fs.mkdirSync(path.dirname(resolvedOutputPath), { recursive: true });
  fs.writeFileSync(resolvedOutputPath, output);
  console.error(`Processed config written to ${resolvedOutputPath}`);
}

function loadMain(scriptPath) {
  const source = fs.readFileSync(scriptPath, 'utf8');

  const context = {
    console,
  };

  const main = vm.runInNewContext(
    `${source}\n;typeof main === 'function' ? main : undefined;`,
    context,
    { filename: scriptPath },
  );

  if (typeof main !== 'function') {
    throw new Error('The script does not define a main(config) function');
  }

  return main;
}

function parseConfig(source) {
  const config = YAML.parse(source);

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('Input YAML must be a config object');
  }

  return config;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const inputSource = readInput(options.inputPath);
  const config = parseConfig(inputSource);
  const processConfig = loadMain(options.scriptPath);
  const processedConfig = processConfig(config);
  const output = YAML.stringify(processedConfig, { lineWidth: 0 });

  writeOutput(options.outputPath, output);
}

try {
  main();
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exit(1);
}
