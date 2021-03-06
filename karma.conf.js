// Karma configuration file, see link for more information
// https://karma-runner.github.io/1.0/config/configuration-file.html
module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine', '@angular/cli'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-coverage-istanbul-reporter'),
      require('karma-spec-reporter'),
      require('@angular/cli/plugins/karma'),
      require('./build/karma.test.reporter.js')
    ],
    client: {
      clearContext: false, // leave Jasmine Spec Runner output visible in browser
      captureConsole: true,
    },
    coverageIstanbulReporter: {
      reports: ['html', 'lcovonly', 'json'],
      fixWebpackSourcePaths: true
    },
    angularCli: {
      environment: 'dev'
    },
    reporters: ['spec', 'kjhtml', 'stratos'],
    port: 9876,
    colors: true,
    logLevel: config.DEBUG,
    autoWatch: true,
    browsers: process.env.CI_ENV ? ['StratosChromeHeadless'] : ['Chrome'],
    customLaunchers: {
      StratosChromeHeadless:{
        base: 'ChromeHeadless',
        flags: ['--no-sandbox']
      }
    },
    singleRun: process.env.CI_ENV ? true : false,
    files: [{
        pattern: './src/frontend/**/*.spec.ts',
        watched: false
      },
      {
        pattern: './node_modules/@angular/material/prebuilt-themes/indigo-pink.css'
      }
    ],
  });
};
