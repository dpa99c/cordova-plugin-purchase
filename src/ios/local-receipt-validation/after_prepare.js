#!/usr/bin/env node

'use strict';

/**
 * This hook makes sure projects using [cordova-plugin-firebase](https://github.com/arnesson/cordova-plugin-firebase)
 * will build properly and have the required key files copied to the proper destinations when the app is build on Ionic Cloud using the package command.
 * Credits: https://github.com/arnesson.
 */
var fs = require('fs');
var path = require("path");
var execSync = require('child_process').execSync;
var utilities = require("./utilities");

var appName;

var IOS_DIR = 'platforms/ios';
var PLUGIN_ID;

var PLATFORM;

var setupEnv = function(){
    appName = utilities.getAppName();
    PLUGIN_ID = utilities.getPluginId();
    PLATFORM = {
        IOS: {
            platformDir: IOS_DIR,
            podFile: IOS_DIR + '/Podfile'
        }
    };
}

var applyPodsPostInstall = function(){
    var podFileModified = false,
        podFilePath = PLATFORM.IOS.podFile,
        podFile = fs.readFileSync(path.resolve(podFilePath)).toString();

    if(podFile.indexOf('cordova-plugin-purchase') === -1){
        var insertionBlock = `
  # cordova-plugin-purchase
  bitcode_strip_path = \`xcrun --find bitcode_strip\`.chop!

  def strip_bitcode_from_framework(bitcode_strip_path, framework_relative_path)
    framework_path = File.join(Dir.pwd, framework_relative_path)
    command = "#{bitcode_strip_path} #{framework_path} -r -o #{framework_path}"
    puts "Stripping bitcode: #{command}"
    system(command)
  end

  framework_paths = [
    "Pods/OpenSSL-Universal/Frameworks/OpenSSL.xcframework/ios-arm64/OpenSSL.framework/OpenSSL",
  ]

  framework_paths.each do |framework_relative_path|
    strip_bitcode_from_framework(bitcode_strip_path, framework_relative_path)
  end
                `;
        var startPostInstallBlock = 'post_install do |installer|';

        var insertingPostInstallBlock = false;
        if(podFile.indexOf('post_install do |installer|') === -1){
            insertingPostInstallBlock = true;
            podFile += `
${startPostInstallBlock}
            `;
        }

        podFile = podFile.replace(startPostInstallBlock, `
${startPostInstallBlock}
${insertionBlock}
        `);

        if(insertingPostInstallBlock){
            podFile += `
end
                `;
        }

        fs.writeFileSync(path.resolve(podFilePath), podFile);
        utilities.log('cordova-plugin-purchase: Applied post install block logic to Podfile');
        podFileModified = true;
    }
    return podFileModified;
};

module.exports = function(context){
    //get platform from the context supplied by cordova
    var platforms = context.opts.platforms;
    utilities.setContext(context);
    setupEnv();

    if(platforms.indexOf('ios') !== -1 && utilities.directoryExists(IOS_DIR)){
        utilities.log('Preparing Purchase plugin on iOS');

        var podFileModified = applyPodsPostInstall();

        if(podFileModified){
            utilities.log('Updating installed Pods');
            execSync('pod install', {
                cwd: path.resolve(PLATFORM.IOS.platformDir),
                encoding: 'utf8'
            });
        }
    }
};

// test direct invocation
/*module.exports({
    opts: {
        platforms: 'ios',
        plugin: {
            id: 'cordova-plugin-purchase'
        }
    }
});*/
