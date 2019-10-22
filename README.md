# Description
This is a PCode emulator for Ghidra.

# Apologies
Listen - this is kinda rough.  It works though!  I'm a little embarrased about the quality of documentation and completeness at the time of release.  This currently works best on x64, x86, and ARM architectures in Ghidra.  It's not tough to add other architectures, I need to implement the initial function call environment for each though and haven't done it.  There are some PCode opcodes not yet implemented - most notably the float operations.  If you needed that I'm sorry, it's on the list of stuff to do.  It needs a testing framework and documentation building.

So, you know, I'm a pro.  This bugs me.  But the day of the talk is here and therefore the time to publish this code is now.

# Installation
From the source directory here...

```
mkdir "$HOME/ghidra_scripts"
ln -s "$PWD" "$HOME/ghidra_scripts/ghidra_pcode_interpreter"
ln -s "$PWD/pcode_interpreter.py" "$HOME/ghidra_scripts/pcode_interpreter.py"
ln -s "$PWD/pcode_inspector.py" "$HOME/ghidra_scripts/pcode_inspector.py"
```

# Usage
Refresh your script list in Ghidra.  Scroll down to the PCode category.  Select the function you want to execute in the decompiler or program listing window.  Make sure you've committed your function prototype (right click in the decompiler and click "Commit Params/Return").  Then double click the `pcode_interpreter.py` script.

Logging currently gets output both to your Ghidra console, but also `/tmp/pcode_interpret.log`.  If you're on a multiuser system please be aware of this temp logging location...  Also, the temp log is a debug log, so it can grow quite large.  It's overwritten each run.

# More Info
My Saintcon 2019 talk on this is at https://github.com/kc0bfv/Saintcon2019GhidraTalk
