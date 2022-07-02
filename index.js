var Node = {
  child: require('child_process'),
  crypto: require('crypto'),
  fs: require('fs'),
  os: require('os'),
  path: require('path'),
  process: process,
  util: require('util')
};

function Attempt(instance, end) {
  var platform = Node.process.platform;
  if (platform === 'darwin') return Mac(instance, end);
  if (platform === 'linux') return Linux(instance, end);
  if (platform === 'win32') return Windows(instance, end);
  end(new Error('Platform not yet supported.'));
}

function EscapeDoubleQuotes(string) {
  if (typeof string !== 'string') throw new Error('Expected a string.');
  return string.replace(/"/g, '\\"');
}

function Exec() {
  if (arguments.length < 1 || arguments.length > 3) {
    throw new Error('Wrong number of arguments.');
  }
  var command = arguments[0];
  var options = {};
  var end = function() {};
  if (typeof command !== 'string') {
    throw new Error('Command should be a string.');
  }
  if (arguments.length === 2) {
    if (Node.util.isObject(arguments[1])) {
      options = arguments[1];
    } else if (Node.util.isFunction(arguments[1])) {
      end = arguments[1];
    } else {
      throw new Error('Expected options or callback.');
    }
  } else if (arguments.length === 3) {
    if (Node.util.isObject(arguments[1])) {
      options = arguments[1];
    } else {
      throw new Error('Expected options to be an object.');
    }
    if (Node.util.isFunction(arguments[2])) {
      end = arguments[2];
    } else {
      throw new Error('Expected callback to be a function.');
    }
  }
  if (/^sudo/i.test(command)) {
    return end(new Error('Command should not be prefixed with "sudo".'));
  }
  if (typeof options.name === 'undefined') {
    var title = Node.process.title;
    if (ValidName(title)) {
      options.name = title;
    } else {
      return end(new Error('process.title cannot be used as a valid name.'));
    }
  } else if (!ValidName(options.name)) {
    var error = '';
    error += 'options.name must be alphanumeric only ';
    error += '(spaces are allowed) and <= 70 characters.';
    return end(new Error(error));
  }
  if (typeof options.icns !== 'undefined') {
    if (typeof options.icns !== 'string') {
      return end(new Error('options.icns must be a string if provided.'));
    } else if (options.icns.trim().length === 0) {
      return end(new Error('options.icns must not be empty if provided.'));
    }
  }
  if (typeof options.env !== 'undefined') {
    if (typeof options.env !== 'object') {
      return end(new Error('options.env must be an object if provided.'));
    } else if (Object.keys(options.env).length === 0) {
      return end(new Error('options.env must not be empty if provided.'));
    } else {
      for (var key in options.env) {
        var value = options.env[key];
        if (typeof key !== 'string' || typeof value !== 'string') {
          return end(
            new Error('options.env environment variables must be strings.')
          );
        }
        // "Environment variable names used by the utilities in the Shell and
        // Utilities volume of IEEE Std 1003.1-2001 consist solely of uppercase
        // letters, digits, and the '_' (underscore) from the characters defined
        // in Portable Character Set and do not begin with a digit. Other
        // characters may be permitted by an implementation; applications shall
        // tolerate the presence of such names."
        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
          return end(
            new Error(
              'options.env has an invalid environment variable name: ' +
              JSON.stringify(key)
            )
          );
        }
        if (/[\r\n]/.test(value)) {
          return end(
            new Error(
              'options.env has an invalid environment variable value: ' +
              JSON.stringify(value)
            )
          );
        }
      }
    }
  }
  var platform = Node.process.platform;
  if (platform !== 'darwin' && platform !== 'linux' && platform !== 'win32') {
    return end(new Error('Platform not yet supported.'));
  }
  var instance = {
    command: command,
    options: options,
    uuid: undefined,
    path: undefined
  };
  Attempt(instance, end);
}

function Linux(instance, end) {
  LinuxBinary(instance,
    function(error, binary) {
      if (error) return end(error);
      var command = [];
      // Preserve current working directory:
      command.push('cd "' + EscapeDoubleQuotes(Node.process.cwd()) + '";');
      // Export environment variables:
      for (var key in instance.options.env) {
        var value = instance.options.env[key];
        command.push('export ' + key + '="' + EscapeDoubleQuotes(value) + '";');
      }
      command.push('"' + EscapeDoubleQuotes(binary) + '"');
      if (/kdesudo/i.test(binary)) {
        command.push(
          '--comment',
          '"' + instance.options.name + ' wants to make changes. ' +
          'Enter your password to allow this."'
        );
        command.push('-d'); // Do not show the command to be run in the dialog.
        command.push('--');
      } else if (/pkexec/i.test(binary)) {
        command.push('--disable-internal-agent');
      }
      var magic = 'SUDOPROMPT\n';
      command.push(
        '/bin/bash -c "echo ' + EscapeDoubleQuotes(magic.trim()) + '; ' +
        EscapeDoubleQuotes(instance.command) +
        '"'
      );
      command = command.join(' ');
      Node.child.exec(command, { encoding: 'utf-8', maxBuffer: MAX_BUFFER },
        function(error, stdout, stderr) {
          // ISSUE 88:
          // We must distinguish between elevation errors and command errors.
          //
          // KDESUDO:
          // kdesudo provides no way to do this. We add a magic marker to know
          // if elevation succeeded. Any error thereafter is a command error.
          //
          // PKEXEC:
          // "Upon successful completion, the return value is the return value of
          // PROGRAM. If the calling process is not authorized or an
          // authorization could not be obtained through authentication or an
          // error occured, pkexec exits with a return value of 127. If the
          // authorization could not be obtained because the user dismissed the
          // authentication dialog, pkexec exits with a return value of 126."
          //
          // However, we do not rely on pkexec's return of 127 since our magic
          // marker is more reliable, and we already use it for kdesudo.
          var elevated = stdout && stdout.slice(0, magic.length) === magic;
          if (elevated) stdout = stdout.slice(magic.length);
          // Only normalize the error if it is definitely not a command error:
          // In other words, if we know that the command was never elevated.
          // We do not inspect error messages beyond NO_POLKIT_AGENT.
          // We cannot rely on English errors because of internationalization.
          if (error && !elevated) {
            if (/No authentication agent found/.test(stderr)) {
              error.message = NO_POLKIT_AGENT;
            } else {
              error.message = PERMISSION_DENIED;
            }
          }
          end(error, stdout, stderr);
        }
      );
    }
  );
}

function LinuxBinary(instance, end) {
  var index = 0;
  // We used to prefer gksudo over pkexec since it enabled a better prompt.
  // However, gksudo cannot run multiple commands concurrently.
  var paths = ['/usr/bin/kdesudo', '/usr/bin/pkexec'];
  function test() {
    if (index === paths.length) {
      return end(new Error('Unable to find pkexec or kdesudo.'));
    }
    var path = paths[index++];
    Node.fs.stat(path,
      function(error) {
        if (error) {
          if (error.code === 'ENOTDIR') return test();
          if (error.code === 'ENOENT') return test();
          end(error);
        } else {
          end(undefined, path);
        }
      }
    );
  }
  test();
}

function Mac(instance, callback) {
  var temp = Node.os.tmpdir();
  if (!temp) return callback(new Error('os.tmpdir() not defined.'));
  var user = Node.process.env.USER; // Applet shell scripts require $USER.
  if (!user) return callback(new Error('env[\'USER\'] not defined.'));
  UUID(instance,
    function(error, uuid) {
      if (error) return callback(error);
      instance.uuid = uuid;
      instance.path = Node.path.join(
        temp,
        instance.uuid,
        instance.options.name + '.app'
      );
      function end(error, stdout, stderr) {
        Remove(Node.path.dirname(instance.path),
          function(errorRemove) {
            if (error) return callback(error);
            if (errorRemove) return callback(errorRemove);
            callback(undefined, stdout, stderr);
          }
        );
      }
      MacApplet(instance,
        function(error, stdout, stderr) {
          if (error) return end(error, stdout, stderr);
          MacIcon(instance,
            function(error) {
              if (error) return end(error);
              MacPropertyList(instance,
                function(error, stdout, stderr) {
                  if (error) return end(error, stdout, stderr);
                  MacCommand(instance,
                    function(error) {
                      if (error) return end(error);
                      MacOpen(instance,
                        function(error, stdout, stderr) {
                          if (error) return end(error, stdout, stderr);
                          MacResult(instance, end);
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
}

function MacApplet(instance, end) {
  var parent = Node.path.dirname(instance.path);
  Node.fs.mkdir(parent,
    function(error) {
      if (error) return end(error);
      var zip = Node.path.join(parent, 'sudo-prompt-applet.zip');
      Node.fs.writeFile(zip, APPLET, 'base64',
        function(error) {
          if (error) return end(error);
          var command = [];
          command.push('/usr/bin/unzip');
          command.push('-o'); // Overwrite any existing applet.
          command.push('"' + EscapeDoubleQuotes(zip) + '"');
          command.push('-d "' + EscapeDoubleQuotes(instance.path) + '"');
          command = command.join(' ');
          Node.child.exec(command, { encoding: 'utf-8' }, end);
        }
      );
    }
  );
}

function MacCommand(instance, end) {
  var path = Node.path.join(
    instance.path,
    'Contents',
    'MacOS',
    'sudo-prompt-command'
  );
  var script = [];
  // Preserve current working directory:
  // We do this for commands that rely on relative paths.
  // This runs in a subshell and will not change the cwd of sudo-prompt-script.
  script.push('cd "' + EscapeDoubleQuotes(Node.process.cwd()) + '"');
  // Export environment variables:
  for (var key in instance.options.env) {
    var value = instance.options.env[key];
    script.push('export ' + key + '="' + EscapeDoubleQuotes(value) + '"');
  }
  script.push(instance.command);
  script = script.join('\n');
  Node.fs.writeFile(path, script, 'utf-8', end);
}

function MacIcon(instance, end) {
  if (!instance.options.icns) return end();
  Node.fs.readFile(instance.options.icns,
    function(error, buffer) {
      if (error) return end(error);
      var icns = Node.path.join(
        instance.path,
        'Contents',
        'Resources',
        'applet.icns'
      );
      Node.fs.writeFile(icns, buffer, end);
    }
  );
}

function MacOpen(instance, end) {
  // We must run the binary directly so that the cwd will apply.
  var binary = Node.path.join(instance.path, 'Contents', 'MacOS', 'applet');
  // We must set the cwd so that the AppleScript can find the shell scripts.
  var options = {
    cwd: Node.path.dirname(binary),
    encoding: 'utf-8'
  };
  // We use the relative path rather than the absolute path. The instance.path
  // may contain spaces which the cwd can handle, but which exec() cannot.
  Node.child.exec('./' + Node.path.basename(binary), options, end);
}

function MacPropertyList(instance, end) {
  // Value must be in single quotes (not double quotes) according to man entry.
  // e.g. defaults write com.companyname.appname "Default Color" '(255, 0, 0)'
  // The defaults command will be changed in an upcoming major release to only
  // operate on preferences domains. General plist manipulation utilities will
  // be folded into a different command-line program.
  var plist = Node.path.join(instance.path, 'Contents', 'Info.plist');
  var path = EscapeDoubleQuotes(plist);
  var key = EscapeDoubleQuotes('CFBundleName');
  var value = instance.options.name + ' Password Prompt';
  if (/'/.test(value)) {
    return end(new Error('Value should not contain single quotes.'));
  }
  var command = [];
  command.push('/usr/bin/defaults');
  command.push('write');
  command.push('"' + path + '"');
  command.push('"' + key + '"');
  command.push("'" + value + "'"); // We must use single quotes for value.
  command = command.join(' ');
  Node.child.exec(command, { encoding: 'utf-8' }, end);
}

function MacResult(instance, end) {
  var cwd = Node.path.join(instance.path, 'Contents', 'MacOS');
  Node.fs.readFile(Node.path.join(cwd, 'code'), 'utf-8',
    function(error, code) {
      if (error) {
        if (error.code === 'ENOENT') return end(new Error(PERMISSION_DENIED));
        end(error);
      } else {
        Node.fs.readFile(Node.path.join(cwd, 'stdout'), 'utf-8',
          function(error, stdout) {
            if (error) return end(error);
            Node.fs.readFile(Node.path.join(cwd, 'stderr'), 'utf-8',
              function(error, stderr) {
                if (error) return end(error);
                code = parseInt(code.trim(), 10); // Includes trailing newline.
                if (code === 0) {
                  end(undefined, stdout, stderr);
                } else {
                  error = new Error(
                    'Command failed: ' + instance.command + '\n' + stderr
                  );
                  error.code = code;
                  end(error, stdout, stderr);
                }
              }
            );
          }
        );
      }
    }
  );
}

function Remove(path, end) {
  if (typeof path !== 'string' || !path.trim()) {
    return end(new Error('Argument path not defined.'));
  }
  var command = [];
  if (Node.process.platform === 'win32') {
    if (/"/.test(path)) {
      return end(new Error('Argument path cannot contain double-quotes.'));
    }
    command.push('rmdir /s /q "' + path + '"');
  } else {
    command.push('/bin/rm');
    command.push('-rf');
    command.push('"' + EscapeDoubleQuotes(Node.path.normalize(path)) + '"');
  }
  command = command.join(' ');
  Node.child.exec(command, { encoding: 'utf-8' }, end);
}

function UUID(instance, end) {
  Node.crypto.randomBytes(256,
    function(error, random) {
      if (error) random = Date.now() + '' + Math.random();
      var hash = Node.crypto.createHash('SHA256');
      hash.update('sudo-prompt-3');
      hash.update(instance.options.name);
      hash.update(instance.command);
      hash.update(random);
      var uuid = hash.digest('hex').slice(-32);
      if (!uuid || typeof uuid !== 'string' || uuid.length !== 32) {
        // This is critical to ensure we don't remove the wrong temp directory.
        return end(new Error('Expected a valid UUID.'));
      }
      end(undefined, uuid);
    }
  );
}

function ValidName(string) {
  // We use 70 characters as a limit to side-step any issues with Unicode
  // normalization form causing a 255 character string to exceed the fs limit.
  if (!/^[a-z0-9 ]+$/i.test(string)) return false;
  if (string.trim().length === 0) return false;
  if (string.length > 70) return false;
  return true;
}

function Windows(instance, callback) {
  var temp = Node.os.tmpdir();
  if (!temp) return callback(new Error('os.tmpdir() not defined.'));
  UUID(instance,
    function(error, uuid) {
      if (error) return callback(error);
      instance.uuid = uuid;
      instance.path = Node.path.join(temp, instance.uuid);
      if (/"/.test(instance.path)) {
        // We expect double quotes to be reserved on Windows.
        // Even so, we test for this and abort if they are present.
        return callback(
          new Error('instance.path cannot contain double-quotes.')
        );
      }
      instance.pathElevate = Node.path.join(instance.path, 'elevate.vbs');
      instance.pathExecute = Node.path.join(instance.path, 'execute.bat');
      instance.pathCommand = Node.path.join(instance.path, 'command.bat');
      instance.pathStdout = Node.path.join(instance.path, 'stdout');
      instance.pathStderr = Node.path.join(instance.path, 'stderr');
      instance.pathStatus = Node.path.join(instance.path, 'status');
      Node.fs.mkdir(instance.path,
        function(error) {
          if (error) return callback(error);
          function end(error, stdout, stderr) {
            Remove(instance.path,
              function(errorRemove) {
                if (error) return callback(error);
                if (errorRemove) return callback(errorRemove);
                callback(undefined, stdout, stderr);
              }
            );
          }
          WindowsWriteExecuteScript(instance,
            function(error) {
              if (error) return end(error);
              WindowsWriteCommandScript(instance,
                function(error) {
                  if (error) return end(error);
                  WindowsElevate(instance,
                    function(error, stdout, stderr) {
                      if (error) return end(error, stdout, stderr);
                      WindowsWaitForStatus(instance,
                        function(error) {
                          if (error) return end(error);
                          WindowsResult(instance, end);
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
}

function WindowsElevate(instance, end) {
  // We used to use this for executing elevate.vbs:
  // var command = 'cscript.exe //NoLogo "' + instance.pathElevate + '"';
  var command = [];
  command.push('powershell.exe');
  command.push('Start-Process');
  command.push('-FilePath');
  // Escape characters for cmd using double quotes:
  // Escape characters for PowerShell using single quotes:
  // Escape single quotes for PowerShell using backtick:
  // See: https://ss64.com/ps/syntax-esc.html
  command.push('"\'' + instance.pathExecute.replace(/'/g, "`'") + '\'"');
  command.push('-WindowStyle hidden');
  command.push('-Verb runAs');
  command = command.join(' ');
  var child = Node.child.exec(command, { encoding: 'utf-8' },
    function(error, stdout, stderr) {
      // We used to return PERMISSION_DENIED only for error messages containing
      // the string 'canceled by the user'. However, Windows internationalizes
      // error messages (issue 96) so now we must assume all errors here are
      // permission errors. This seems reasonable, given that we already run the
      // user's command in a subshell.
      if (error) return end(new Error(PERMISSION_DENIED), stdout, stderr);
      end();
    }
  );
  child.stdin.end(); // Otherwise PowerShell waits indefinitely on Windows 7.
}

function WindowsResult(instance, end) {
  Node.fs.readFile(instance.pathStatus, 'utf-8',
    function(error, code) {
      if (error) return end(error);
      Node.fs.readFile(instance.pathStdout, 'utf-8',
        function(error, stdout) {
          if (error) return end(error);
          Node.fs.readFile(instance.pathStderr, 'utf-8',
            function(error, stderr) {
              if (error) return end(error);
              code = parseInt(code.trim(), 10);
              if (code === 0) {
                end(undefined, stdout, stderr);
              } else {
                error = new Error(
                  'Command failed: ' + instance.command + '\r\n' + stderr
                );
                error.code = code;
                end(error, stdout, stderr);
              }
            }
          );
        }
      );
    }
  );
}

function WindowsWaitForStatus(instance, end) {
  // VBScript cannot wait for the elevated process to finish so we have to poll.
  // VBScript cannot return error code if user does not grant permission.
  // PowerShell can be used to elevate and wait on Windows 10.
  // PowerShell can be used to elevate on Windows 7 but it cannot wait.
  // powershell.exe Start-Process cmd.exe -Verb runAs -Wait
  Node.fs.stat(instance.pathStatus,
    function(error, stats) {
      if ((error && error.code === 'ENOENT') || stats.size < 2) {
        // Retry if file does not exist or is not finished writing.
        // We expect a file size of 2. That should cover at least "0\r".
        // We use a 1 second timeout to keep a light footprint for long-lived
        // sudo-prompt processes.
        setTimeout(
          function() {
            // If administrator has no password and user clicks Yes, then
            // PowerShell returns no error and execute (and command) never runs.
            // We check that command output has been redirected to stdout file:
            Node.fs.stat(instance.pathStdout,
              function(error) {
                if (error) return end(new Error(PERMISSION_DENIED));
                WindowsWaitForStatus(instance, end);
              }
            );
          },
          1000
        );
      } else if (error) {
        end(error);
      } else {
        end();
      }
    }
  );
}

function WindowsWriteCommandScript(instance, end) {
  var cwd = Node.process.cwd();
  if (/"/.test(cwd)) {
    // We expect double quotes to be reserved on Windows.
    // Even so, we test for this and abort if they are present.
    return end(new Error('process.cwd() cannot contain double-quotes.'));
  }
  var script = [];
  script.push('@echo off');
  // Set code page to UTF-8:
  script.push('chcp 65001>nul');
  // Preserve current working directory:
  // We pass /d as an option in case the cwd is on another drive (issue 70).
  script.push('cd /d "' + cwd + '"');
  // Export environment variables:
  for (var key in instance.options.env) {
    // "The characters <, >, |, &, ^ are special command shell characters, and
    // they must be preceded by the escape character (^) or enclosed in
    // quotation marks. If you use quotation marks to enclose a string that
    // contains one of the special characters, the quotation marks are set as
    // part of the environment variable value."
    // In other words, Windows assigns everything that follows the equals sign
    // to the value of the variable, whereas Unix systems ignore double quotes.
    var value = instance.options.env[key];
    script.push('set ' + key + '=' + value.replace(/([<>\\|&^])/g, '^$1'));
  }
  script.push(instance.command);
  script = script.join('\r\n');
  Node.fs.writeFile(instance.pathCommand, script, 'utf-8', end);
}

function WindowsWriteElevateScript(instance, end) {
  // We do not use VBScript to elevate since it does not return an error if
  // the user does not grant permission. This is here for reference.
  // var script = [];
  // script.push('Set objShell = CreateObject("Shell.Application")');
  // script.push(
  // 'objShell.ShellExecute "' + instance.pathExecute + '", "", "", "runas", 0'
  // );
  // script = script.join('\r\n');
  // Node.fs.writeFile(instance.pathElevate, script, 'utf-8', end);
}

function WindowsWriteExecuteScript(instance, end) {
  var script = [];
  script.push('@echo off');
  script.push(
    'call "' + instance.pathCommand + '"' +
    ' > "' + instance.pathStdout + '" 2> "' + instance.pathStderr + '"'
  );
  script.push('(echo %ERRORLEVEL%) > "' + instance.pathStatus + '"');
  script = script.join('\r\n');
  Node.fs.writeFile(instance.pathExecute, script, 'utf-8', end);
}

module.exports.exec = Exec;

// We used to expect that applet.app would be included with this module.
// This could not be copied when sudo-prompt was packaged within an asar file.
// We now store applet.app as a zip file in base64 within index.js instead.
// To recreate: "zip -r ../applet.zip Contents" (with applet.app as CWD).
// The zip file must not include applet.app as the root directory so that we
// can extract it directly to the target app directory.
//
// To update the applet, follow these steps:
// * open main.scpt in macOS Script Editor and edit it as needed
// * select File | Export... (file format: Application)
// * replace the `applet` in `Contents/MacOS`
// * `zip -r ../applet.zip Contents`
// * base64 encode the zip file
// * replace the contents of the `APPLET` variable
var APPLET = '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';

var PERMISSION_DENIED = 'User did not grant permission.';
var NO_POLKIT_AGENT = 'No polkit authentication agent found.';

// See issue 66:
var MAX_BUFFER = 134217728;
