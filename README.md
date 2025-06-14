# Sign with Key Test

A TypeScript project for key-based signing operations.

## Prerequisites

- Node.js (v14 or higher)
- npm (comes with Node.js)

## Installation

1. Clone the repository

2. Install dependencies:

```bash
npm install
```

## Building and Running

### Build the Project

To compile TypeScript to JavaScript:

```bash
npm run build
```

This will create a `dist` directory with the compiled JavaScript files.

### Run the Project

After building, you can run the project with:

```bash
npm run start
```

Or run it directly with:

```bash
node dist/index.js
```

## Project Structure

- `src/` - Source TypeScript files
  - `index.ts` - Main entry point
  - `signCreateCredChallenge.ts` - Signing implementation for credential challenge
  - `signUserActionChallenge.ts` - Signing implementation for user action challenge
  - `keyManager.ts` - Key pair management
- `dist/` - Compiled JavaScript files (created after build)

## Development

To modify the code:

1. Edit the TypeScript files in the `src` directory
2. Rebuild the project with `npm run build`
3. Run the updated code with `npm run start`
