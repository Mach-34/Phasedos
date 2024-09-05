/** @type {import('ts-jest/dist/types').InitialOptionsTsJest} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    transform: {
        '^.+\\.tsx?$': 'ts-jest', // Transforms TypeScript files
        '^.+\\.jsx?$': 'babel-jest', // Transforms JavaScript files
    },
    transformIgnorePatterns: [
        '/node_modules/(?!grapevine_wasm).+\\.js$', // Transform ES modules in specific packages
    ],
    extensionsToTreatAsEsm: ['.ts'], // Treat TypeScript and JavaScript files as ES modules
    globals: {
        'ts-jest': {
            useESM: true, // Enable ESM support in ts-jest
        },
    },
};