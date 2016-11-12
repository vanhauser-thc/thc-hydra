#ifdef DEBUG	/* keep these macros common so they are same for both versions */
CONST int debugCompile	=	1;
extern  int	debug;
extern  void DebugIO(CONST char *s);	/* display the debug output */

#define DebugDump(x,s,R,XOR,doRot,showT,needBswap)	\
	{ if (debug) _Dump(x,s,R,XOR,doRot,showT,needBswap,t0,t1); }
#define	DebugDumpKey(key) { if (debug) _DumpKey(key); }
#define	IV_ROUND	-100
	
void _Dump(CONST void *p,CONST char *s,int R,int XOR,int doRot,int showT,int needBswap,
		   DWORD t0,DWORD t1)
	{
	char line[512];	/* build output here */
	int  i,n;
	DWORD q[4];

	if (R == IV_ROUND)
		sprintf(line,"%sIV:    ",s);
	else
		sprintf(line,"%sR[%2d]: ",s,R);
	for (n=0;line[n];n++) ;
	
	for (i=0;i<4;i++)
		{
		q[i]=((CONST DWORD *)p)[i^(XOR)];
		if (needBswap) q[i]=Bswap(q[i]);
		}

	sprintf(line+n,"x= %08lX  %08lX  %08lX  %08lX.",
			ROR(q[0],doRot*(R  )/2),
			ROL(q[1],doRot*(R  )/2),
			ROR(q[2],doRot*(R+1)/2),
			ROL(q[3],doRot*(R+1)/2));
	for (;line[n];n++) ;

	if (showT)
		sprintf(line+n,"    t0=%08lX. t1=%08lX.",t0,t1);
	for (;line[n];n++) ;

	sprintf(line+n,"\n");
	DebugIO(line);
	}

void _DumpKey(CONST keyInstance *key)
	{
	char	line[512];
	int		i;
	int		k64Cnt=(key->keyLen+63)/64;	/* round up to next multiple of 64 bits */
	int		subkeyCnt = ROUND_SUBKEYS + 2*key->numRounds;

	sprintf(line,";\n;makeKey:   Input key            -->  S-box key     [%s]\n",
		   (key->direction == DIR_ENCRYPT) ? "Encrypt" : "Decrypt");
	DebugIO(line);
	for (i=0;i<k64Cnt;i++)	/* display in RS format */
		{
		sprintf(line,";%12s %08lX %08lX  -->  %08lX\n","",
			   key->key32[2*i+1],key->key32[2*i],key->sboxKeys[k64Cnt-1-i]);
		DebugIO(line);
		}
	sprintf(line,";%11sSubkeys\n","");
	DebugIO(line);
	for (i=0;i<subkeyCnt/2;i++)
		{
		sprintf(line,";%12s %08lX %08lX%s\n","",key->subKeys[2*i],key->subKeys[2*i+1],
			  (2*i ==  INPUT_WHITEN) ? "   Input whiten" :
			  (2*i == OUTPUT_WHITEN) ? "  Output whiten" :
		      (2*i == ROUND_SUBKEYS) ? "  Round subkeys" : "");
		DebugIO(line);
		}
	DebugIO(";\n");
	}
#else
CONST int debugCompile	=	0;
#define DebugDump(x,s,R,XOR,doRot,showT,needBswap)
#define	DebugDumpKey(key)
#endif
