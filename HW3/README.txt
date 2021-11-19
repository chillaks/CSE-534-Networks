The following project has been done in an Ubuntu based EC2 instance. XTerm was configured from EC2 back to my local Mac M1 through XQuartz. Make sure to enable X11Forwarding on both systems in order to make it work. Also, SSH from local to EC2 is done with the -X option. If you get X11 authentication errors when running xterm inside mininet, copy the xauth $DISPLAY variable from the user's env to the root user's env by running the following sequence of commands (user below is ubuntu when using EC2):
1. user@host > xauth list $DISPLAY
2. Copy contents of above command
3. sudo -s
4. root@host > xauth add <paste_step_2>
5. exit
6. Now run the mininet program and use xterm successfully
