#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void pwncollege();

int main(int argc,char *argv[])
{
    pwncollege();
    return 0;
}

void pwncollege()
{
    int nb_args=345; // nb args + 1
    char *args[nb_args+1]; // nb args + null
    int status,cpid;
    // fill args
    args[0] = "env";
    args[1] = "-i";
    args[2] = "220=afcecjqyib";
    args[3] = "/challenge/run";
    for(int i=4;i<nb_args;i++)
    {
        args[i] = "frvpvgzvbd";
    }
    cpid=fork(); // make child process
    if(cpid==0)
    {
        execvp("/usr/bin/env", args); // start child process
    } 
    waitpid(-1,&status,0);
}

