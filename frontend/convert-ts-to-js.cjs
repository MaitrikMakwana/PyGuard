// convert-ts-to-js.cjs
// Node.js script to convert all .ts/.tsx files to .js/.jsx, remove TypeScript syntax, and update import/export extensions
const fs = require('fs');
const path = require('path');

const walk = (dir, filelist = []) => {
  fs.readdirSync(dir).forEach(file => {
    const filepath = path.join(dir, file);
    if (fs.statSync(filepath).isDirectory()) {
      filelist = walk(filepath, filelist);
    } else if (filepath.endsWith('.ts') || filepath.endsWith('.tsx')) {
      filelist.push(filepath);
    }
  });
  return filelist;
};

const removeTypescript = (code) => {
  // Remove type annotations, interfaces, and types
  return code
    // Remove type annotations (simple)
    .replace(/: [a-zA-Z0-9_\[\]\|<>]+/g, '')
    // Remove interface/type declarations
    .replace(/interface [^{]+{[^}]+}/g, '')
    .replace(/type [^{=]+=[^;]+;/g, '')
    // Remove import type
    .replace(/import type /g, 'import ')
    // Remove as type assertions
    .replace(/ as [a-zA-Z0-9_\[\]\|<>]+/g, '')
    // Remove <Type> assertions
    .replace(/<([a-zA-Z0-9_\[\]\|<>]+)>/g, '')
    // Remove declare keyword
    .replace(/declare /g, '');
};

const updateImports = (code, ext) => {
  // Update import/export extensions
  return code.replace(/(from ['\"].+?)\.(ts|tsx)(['\"])/g, `$1.${ext}$3`);
};

const files = walk('.');
files.forEach(file => {
  const isTSX = file.endsWith('.tsx');
  const newExt = isTSX ? '.jsx' : '.js';
  const newFile = file.replace(/\.tsx?$/, newExt);
  let code = fs.readFileSync(file, 'utf8');
  code = removeTypescript(code);
  code = updateImports(code, isTSX ? 'jsx' : 'js');
  fs.writeFileSync(newFile, code, 'utf8');
  if (newFile !== file) fs.unlinkSync(file);
  console.log(`Converted: ${file} -> ${newFile}`);
}); 