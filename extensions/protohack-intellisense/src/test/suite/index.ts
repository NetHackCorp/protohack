import * as path from 'path';
import Mocha from 'mocha';
import { glob } from 'glob';

export async function run(): Promise<void> {
  const mocha = new Mocha({ ui: 'bdd', color: true });
  const testsRoot = path.resolve(__dirname, '.');

  const files = await glob('**/*.test.js', { cwd: testsRoot });
  files.forEach(file => mocha.addFile(path.resolve(testsRoot, file)));

  return new Promise((resolve, reject) => {
    try {
      mocha.run(failures => {
        if (failures > 0) {
          reject(new Error(`${failures} tests failed.`));
        } else {
          resolve();
        }
      });
    } catch (error) {
      reject(error);
    }
  });
}
