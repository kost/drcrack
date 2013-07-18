/* rcalc.cpp
 *	
 *	calculate success probability based off the rainbowcrack dude's matlab script
 *	ported from a ported version of rainbowcalc i made :S dont ask but the code is sloppy in many places so enjoy!
 *	there is no real error checking or proper testing if it works, feel free to re-write this with getop as well
 *
 *	Compiles OK with gcc
 */


	//N is the keyspace
	//t is the Rainbow Chain length
	//m is the Rainbo Chain count
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

double calcProb(double N,double t,double m);
void fsize(double chains, double amt);
void usage(char *appname);


double calcProb(double N,double t,double m)
{
	double ret=0;
	double arr[99999]={0}; //i like big arrays
	double tt=0;
	arr[1] = N * (1 - exp(-m / N));
	
	//Calculating Success Step 1
	for (int i = 2; i <= (t-1); i++)
		arr[i]= N * (1 - exp(-arr[i - 1] / N));
	
	//Calculating Success Step 2
	ret = 1;
	for (int ii = 1; ii <= (t - 1);ii++)
	    ret *= (1 - arr[ii] / N);
	ret = 1 - ret;

	return ret;
}


//calculate the filesize of a table
void fsize(double chains, double amt)
{
	double temp = chains * amt / 1048576 * 16;
	if (temp > 1000)
	{
		temp /=1000;
		printf ("%.2f GB",temp);
	}
	else
		printf ("%.2f MB",temp);
}

void usage(char *appname) {
	printf("Caculates the success rate and filesize of rainbow tables or outputs the config\n");
	printf("Caution: No Real Error Checking!\n");
	printf("\nCalculation:\n%s chainlen chains tables parts keyspace\n",appname);
	printf("eg: %s 2400 40000000 5 1 8000000\n",appname);
	
	printf("\nOutput:\n%s chainlen chains tables parts keyspace algorithm\n",appname);
	printf("eg:%s 2400 40000000 5 1 8000000 md4\n\n",appname);

	printf("chainlen:  Chain Length\n");
	printf("chains:    Number of Chains\n");
	printf("tables:    Number of Tables\n");
	printf("parts:     Number of Parts to Split Table Into, Enter 1 For No Splitting\n");
	printf("keyspace:  Size of the keyspace\n");
	printf("algorithm: Hash Alorithm Used in Output\n");
}

int main(int argc, char *argv[])
{
	double N=0; //8353082582;
	double t=0; //2400;
	double m=0; //4000000;
	double p=0;
	double mm=0;

	int tables=0;
	int keystart=0;
	int keyend=0;
	int chars=0;
	int split=1;

	char hash[50]={'\0'};
	char charset[50]={'\0'};
	

	if (argc == 6 || argc ==7)
	{
		t=atof(argv[1]);
		m=mm=atof(argv[2]);
		tables=atoi(argv[3]);
		split=atoi(argv[4]);
		
		N=atoi(argv[5]);
	}
	
	//doesnt look that elegant using this check twice but ahh well
	if (argc==6) //no output, only calculate
	{
	

		//success probability	
		p = calcProb(N, t, mm);

		//account for split tables
		if (split > 1)
			m=mm / split;
		else
			m=mm;
			
		//Total success probability
		printf ("Success %.6f%% \n", ( (1 - pow(1 - p,tables)) * 100) );
		
		fsize(m,1);
		printf(" per table\n");
		fsize(mm,tables);
		printf(" total\n");
	}
	else if (argc==7) //output
	{
		strcpy(hash,argv[6]);

		//Creating Output"
		for(int a = 1; a <= tables; a++)
		{
		  //echo "table: ".(a - 1)." ==> ".( 1- pow(1 - p,a) )."<br>";
			if (split == 1)
			//output unsplit tables
	    		printf("rtgen %s %s %d %d %d %.0f %.0f all\n", hash, charset, keystart, keyend, (a - 1), t, m);
				
			else
			{
			  for (int b = 0; b < split; b++)
	      		//output split tables
				printf("rtgen %s %s %d %d %d %.0f %.0f #%d\n", hash, charset, keystart, keyend, (a-1), t, m, b);
	  		} //end if    
		} //a
	} //end big if
	else
	{
		usage(argv[0]);
		exit(1);
	}
	return 0;
}
