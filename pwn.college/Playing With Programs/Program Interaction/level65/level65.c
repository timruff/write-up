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
}

void pwncollege()
{
    int pipefd1[2],pipefd2[2], status;
    pid_t cpid;
    pipe(pipefd1); // make first pipe
    pipe(pipefd2); // make second pipe
    
    cpid=fork();  // make first child
    if(cpid==0)
    {
        close(pipefd1[0]);  // close in pipe
        dup2(pipefd1[1], STDOUT_FILENO); // out frop pipe
        execlp("/usr/bin/rev","rev",(char *) NULL); // exec child
    }

    close(pipefd1[1]);  // close out pipe
    cpid=fork();  // make second child
    if(cpid==0)
    {
        close(pipefd2[0]);  // close out don't use
        dup2(pipefd1[0], STDIN_FILENO); // in from pipe
        dup2(pipefd2[1], STDOUT_FILENO); // out from pipe
        execlp("/usr/bin/rev","rev",(char *) NULL); // exec child
    }

    close(pipefd1[0]); // close pipes EOF run
    close(pipefd2[1]); // second child don't get EOF, parent make it

    cpid = fork();
    if (cpid == 0)
    {
        dup2(pipefd2[0],STDIN_FILENO); // take in pipe
        execlp("/challenge/run","run",(char *) NULL);
    }
    close(pipefd2[0]); // cloe pipe

    // wait child
    waitpid(-1,&status,0);
    waitpid(-1,&status,0);
    waitpid(-1,&status,0);
}

