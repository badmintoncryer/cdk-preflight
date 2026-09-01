import { awscdk, javascript } from 'projen';
const project = new awscdk.AwsCdkConstructLibrary({
  author: 'Kazuho Cryer-Shinozuka',
  authorAddress: 'malaysia.cryer@gmail.com',
  cdkVersion: '2.189.1',
  jsiiVersion: '~6.0.0',
  name: 'cdk-preflight',
  packageManager: javascript.NodePackageManager.NPM,
  projenrcTs: true,
  repositoryUrl: 'https://github.com/malaysia.cryer/cdk-preflight.git',

  // defaultReleaseBranch: "main",  /* The name of the main release branch. */
  // deps: [],                      /* Runtime dependencies of this module. */
  // description: undefined,        /* The description is just a string that helps people understand the purpose of the package. */
  // devDeps: [],                   /* Build dependencies for this module. */
  // packageName: undefined,        /* The "name" in package.json. */
});
project.synth();