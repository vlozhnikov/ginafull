#include "StdAfx.h"
#include <string.h>
#include "bf.h"

#define ROUNDS 16   
typedef long LONG;
typedef WORD UWORD;
typedef BYTE UBYTE;

LONG f(LONG x);
void DecryptBlock(LONG *Xl,LONG *Xr);
void EncryptBlock(LONG *Xl,LONG *Xr);
void GetWord(LONG *LongValue,const CHAR* CryptBuffer,INT Offset);
void PutWord(const LONG *LongValue,CHAR* CryptBuffer,INT Offset);
	
LONG m_sBox[4][256];                                
LONG m_pBox[ROUNDS+2];                              
BYTE isUsed/*=FALSE*/;
BYTE BF_KEY[]={
				0xa0,0x82,0xac,0x8a,0x98,0x40,0xae,0x92,0x9c,0xa6,0x9e,0x86,0x96,0x40,0xd6,0xca,
				0xf2,0x40,0xcc,0xde,0xe4,0x40,0x84,0xd8,0xde,0xee,0x8c,0xd2,0xe6,0xd0,0x40,0xca,
				0xdc,0xc6,0xe4,0xe0,0xf2,0xe0,0xe8,0xd2,0xde,0xdc,0x40,0xee,0xd2,0xe8,0xd0,0x40,
				0xc2,0x40,0xd8,0xde,0xe8,0x40,0xde,0xcc,0x40,0xc6,0xd0,0xc2,0xe4,0xc2,0xc6,0xe8,
				0xca,0xe4,0x40,0xcc,0xde,0xe4,0x40,0xc4,0xca,0xe8,0xe8,0xca,0xe4,0x40,0xe6,0xca,
				0xc6,0xea,0xe4,0xd2,0xe8,0xf2,0x40,0xd8,0xca,0xec,0xca,0xd8,0x40,0x5a,0x40,0xe6,
				0xd0,0xde,0xea,0xd8,0xc8,0x40,0xc4,0xca,0x40,0xd2,0xda,0xe0,0xde,0xe6,0xe6,0xd2,
				0xc4,0xd8,0xca,0x40,0xe8,0xde,0x40,0xc6,0xe4,0xc2,0xc6,0xd6,0x42
			   };
#define BF_KEY_LEN 125
     
	INT BF_reset()
	{
		isUsed=FALSE;
		return 0;
	}     
	
	INT BF_isset()
	{
		return isUsed;
	}
    /*
    	initialize blowfish keys
    */ 
	INT BF_set()
	{
		m_pBox[0] = (LONG)0x243F6A88;m_pBox[1] = (LONG)0x85A308D3;m_pBox[2] = (LONG)0x13198A2E;
		m_pBox[3] = (LONG)0x3707344;m_pBox[4] = (LONG)0xA4093822;m_pBox[5] = (LONG)0x299F31D0;
		m_pBox[6] = (LONG)0x82EFA98;m_pBox[7] = (LONG)0xEC4E6C89;m_pBox[8] = (LONG)0x452821E6;
		m_pBox[9] = (LONG)0x38D01377;m_pBox[10] = (LONG)0xBE5466CF;m_pBox[11] = (LONG)0x34E90C6C;
		m_pBox[12] = (LONG)0xC0AC29B7;m_pBox[13] = (LONG)0xC97C50DD;m_pBox[14] = (LONG)0x3F84D5B5;
		m_pBox[15] = (LONG)0xB5470917;m_pBox[16] = (LONG)0x9216D5D9;m_pBox[17] = (LONG)0x8979FB1B;
		m_sBox[0][0] = (LONG)0xD1310BA6;m_sBox[1][0] = (LONG)0x98DFB5AC;m_sBox[2][0] = (LONG)0x2FFD72DB;
		m_sBox[3][0] = (LONG)0xD01ADFB7;m_sBox[0][1] = (LONG)0xB8E1AFED;m_sBox[1][1] = (LONG)0x6A267E96;
		m_sBox[2][1] = (LONG)0xBA7C9045;m_sBox[3][1] = (LONG)0xF12C7F99;m_sBox[0][2] = (LONG)0x24A19947;
		m_sBox[1][2] = (LONG)0xB3916CF7;m_sBox[2][2] = (LONG)0x801F2E2;m_sBox[3][2] = (LONG)0x858EFC16;
		m_sBox[0][3] = (LONG)0x636920D8;m_sBox[1][3] = (LONG)0x71574E69;m_sBox[2][3] = (LONG)0xA458FEA3;
		m_sBox[3][3] = (LONG)0xF4933D7E;m_sBox[0][4] = (LONG)0xD95748F;m_sBox[1][4] = (LONG)0x728EB658;
		m_sBox[2][4] = (LONG)0x718BCD58;m_sBox[3][4] = (LONG)0x82154AEE;m_sBox[0][5] = (LONG)0x7B54A41D;
		m_sBox[1][5] = (LONG)0xC25A59B5;m_sBox[2][5] = (LONG)0x9C30D539;m_sBox[3][5] = (LONG)0x2AF26013;
		m_sBox[0][6] = (LONG)0xC5D1B023;m_sBox[1][6] = (LONG)0x286085F0;m_sBox[2][6] = (LONG)0xCA417918;
		m_sBox[3][6] = (LONG)0xB8DB38EF;m_sBox[0][7] = (LONG)0x8E79DCB0;m_sBox[1][7] = (LONG)0x603A180E;
		m_sBox[2][7] = (LONG)0x6C9E0E8B;m_sBox[3][7] = (LONG)0xB01E8A3E;m_sBox[0][8] = (LONG)0xD71577C1;
		m_sBox[1][8] = (LONG)0xBD314B27;m_sBox[2][8] = (LONG)0x78AF2FDA;m_sBox[3][8] = (LONG)0x55605C60;
		m_sBox[0][9] = (LONG)0xE65525F3;m_sBox[1][9] = (LONG)0xAA55AB94;m_sBox[2][9] = (LONG)0x57489862;
		m_sBox[3][9] = (LONG)0x63E81440;m_sBox[0][10] = (LONG)0x55CA396A;m_sBox[1][10] = (LONG)0x2AAB10B6;
		m_sBox[2][10] = (LONG)0xB4CC5C34;m_sBox[3][10] = (LONG)0x1141E8CE;m_sBox[0][11] = (LONG)0xA15486AF;
		m_sBox[1][11] = (LONG)0x7C72E993;m_sBox[2][11] = (LONG)0xB3EE1411;m_sBox[3][11] = (LONG)0x636FBC2A;
		m_sBox[0][12] = (LONG)0x2BA9C55D;m_sBox[1][12] = (LONG)0x741831F6;m_sBox[2][12] = (LONG)0xCE5C3E16;
		m_sBox[3][12] = (LONG)0x9B87931E;m_sBox[0][13] = (LONG)0xAFD6BA33;m_sBox[1][13] = (LONG)0x6C24CF5C;
		m_sBox[2][13] = (LONG)0x7A325381;m_sBox[3][13] = (LONG)0x28958677;m_sBox[0][14] = (LONG)0x3B8F4898;
		m_sBox[1][14] = (LONG)0x6B4BB9AF;m_sBox[2][14] = (LONG)0xC4BFE81B;m_sBox[3][14] = (LONG)0x66282193;
		m_sBox[0][15] = (LONG)0x61D809CC;m_sBox[1][15] = (LONG)0xFB21A991;m_sBox[2][15] = (LONG)0x487CAC60;
		m_sBox[3][15] = (LONG)0x5DEC8032;m_sBox[0][16] = (LONG)0xEF845D5D;m_sBox[1][16] = (LONG)0xE98575B1;
		m_sBox[2][16] = (LONG)0xDC262302;m_sBox[3][16] = (LONG)0xEB651B88;m_sBox[0][17] = (LONG)0x23893E81;
		m_sBox[1][17] = (LONG)0xD396ACC5;m_sBox[2][17] = (LONG)0xF6D6FF3;m_sBox[3][17] = (LONG)0x83F44239;
		m_sBox[0][18] = (LONG)0x2E0B4482;m_sBox[1][18] = (LONG)0xA4842004;m_sBox[2][18] = (LONG)0x69C8F04A;
		m_sBox[3][18] = (LONG)0x9E1F9B5E;m_sBox[0][19] = (LONG)0x21C66842;m_sBox[1][19] = (LONG)0xF6E96C9A;
		m_sBox[2][19] = (LONG)0x670C9C61;m_sBox[3][19] = (LONG)0xABD388F0;m_sBox[0][20] = (LONG)0x6A51A0D2;
		m_sBox[1][20] = (LONG)0xD8542F68;m_sBox[2][20] = (LONG)0x960FA728;m_sBox[3][20] = (LONG)0xAB5133A3;
		m_sBox[0][21] = (LONG)0x6EEF0B6C;m_sBox[1][21] = (LONG)0x137A3BE4;m_sBox[2][21] = (LONG)0xBA3BF050;
		m_sBox[3][21] = (LONG)0x7EFB2A98;m_sBox[0][22] = (LONG)0xA1F1651D;m_sBox[1][22] = (LONG)0x39AF0176;
		m_sBox[2][22] = (LONG)0x66CA593E;m_sBox[3][22] = (LONG)0x82430E88;m_sBox[0][23] = (LONG)0x8CEE8619;
		m_sBox[1][23] = (LONG)0x456F9FB4;m_sBox[2][23] = (LONG)0x7D84A5C3;m_sBox[3][23] = (LONG)0x3B8B5EBE;
		m_sBox[0][24] = (LONG)0xE06F75D8;m_sBox[1][24] = (LONG)0x85C12073;m_sBox[2][24] = (LONG)0x401A449F;
		m_sBox[3][24] = (LONG)0x56C16AA6;m_sBox[0][25] = (LONG)0x4ED3AA62;m_sBox[1][25] = (LONG)0x363F7706;
		m_sBox[2][25] = (LONG)0x1BFEDF72;m_sBox[3][25] = (LONG)0x429B023D;m_sBox[0][26] = (LONG)0x37D0D724;
		m_sBox[1][26] = (LONG)0xD00A1248;m_sBox[2][26] = (LONG)0xDB0FEAD3;m_sBox[3][26] = (LONG)0x49F1C09B;
		m_sBox[0][27] = (LONG)0x75372C9;m_sBox[1][27] = (LONG)0x80991B7B;m_sBox[2][27] = (LONG)0x25D479D8;
		m_sBox[3][27] = (LONG)0xF6E8DEF7;m_sBox[0][28] = (LONG)0xE3FE501A;m_sBox[1][28] = (LONG)0xB6794C3B;
		m_sBox[2][28] = (LONG)0x976CE0BD;m_sBox[3][28] = (LONG)0x4C006BA;m_sBox[0][29] = (LONG)0xC1A94FB6;
		m_sBox[1][29] = (LONG)0x409F60C4;m_sBox[2][29] = (LONG)0x5E5C9EC2;m_sBox[3][29] = (LONG)0x196A2463;
		m_sBox[0][30] = (LONG)0x68FB6FAF;m_sBox[1][30] = (LONG)0x3E6C53B5;m_sBox[2][30] = (LONG)0x1339B2EB;
		m_sBox[3][30] = (LONG)0x3B52EC6F;m_sBox[0][31] = (LONG)0x6DFC511F;m_sBox[1][31] = (LONG)0x9B30952C;
		m_sBox[2][31] = (LONG)0xCC814544;m_sBox[3][31] = (LONG)0xAF5EBD09;m_sBox[0][32] = (LONG)0xBEE3D004;
		m_sBox[1][32] = (LONG)0xDE334AFD;m_sBox[2][32] = (LONG)0x660F2807;m_sBox[3][32] = (LONG)0x192E4BB3;
		m_sBox[0][33] = (LONG)0xC0CBA857;m_sBox[1][33] = (LONG)0x45C8740F;m_sBox[2][33] = (LONG)0xD20B5F39;
		m_sBox[3][33] = (LONG)0xB9D3FBDB;m_sBox[0][34] = (LONG)0x5579C0BD;m_sBox[1][34] = (LONG)0x1A60320A;
		m_sBox[2][34] = (LONG)0xD6A100C6;m_sBox[3][34] = (LONG)0x402C7279;m_sBox[0][35] = (LONG)0x679F25FE;
		m_sBox[1][35] = (LONG)0xFB1FA3CC;m_sBox[2][35] = (LONG)0x8EA5E9F8;m_sBox[3][35] = (LONG)0xDB3222F8;
		m_sBox[0][36] = (LONG)0x3C7516DF;m_sBox[1][36] = (LONG)0xFD616B15;m_sBox[2][36] = (LONG)0x2F501EC8;
		m_sBox[3][36] = (LONG)0xAD0552AB;m_sBox[0][37] = (LONG)0x323DB5FA;m_sBox[1][37] = (LONG)0xFD238760;
		m_sBox[2][37] = (LONG)0x53317B48;m_sBox[3][37] = (LONG)0x3E00DF82;m_sBox[0][38] = (LONG)0x9E5C57BB;
		m_sBox[1][38] = (LONG)0xCA6F8CA0;m_sBox[2][38] = (LONG)0x1A87562E;m_sBox[3][38] = (LONG)0xDF1769DB;
		m_sBox[0][39] = (LONG)0xD542A8F6;m_sBox[1][39] = (LONG)0x287EFFC3;m_sBox[2][39] = (LONG)0xAC6732C6;
		m_sBox[3][39] = (LONG)0x8C4F5573;m_sBox[0][40] = (LONG)0x695B27B0;m_sBox[1][40] = (LONG)0xBBCA58C8;
		m_sBox[2][40] = (LONG)0xE1FFA35D;m_sBox[3][40] = (LONG)0xB8F011A0;m_sBox[0][41] = (LONG)0x10FA3D98;
		m_sBox[1][41] = (LONG)0xFD2183B8;m_sBox[2][41] = (LONG)0x4AFCB56C;m_sBox[3][41] = (LONG)0x2DD1D35B;
		m_sBox[0][42] = (LONG)0x9A53E479;m_sBox[1][42] = (LONG)0xB6F84565;m_sBox[2][42] = (LONG)0xD28E49BC;
		m_sBox[3][42] = (LONG)0x4BFB9790;m_sBox[0][43] = (LONG)0xE1DDF2DA;m_sBox[1][43] = (LONG)0xA4CB7E33;
		m_sBox[2][43] = (LONG)0x62FB1341;m_sBox[3][43] = (LONG)0xCEE4C6E8;m_sBox[0][44] = (LONG)0xEF20CADA;
		m_sBox[1][44] = (LONG)0x36774C01;m_sBox[2][44] = (LONG)0xD07E9EFE;m_sBox[3][44] = (LONG)0x2BF11FB4;
		m_sBox[0][45] = (LONG)0x95DBDA4D;m_sBox[1][45] = (LONG)0xAE909198;m_sBox[2][45] = (LONG)0xEAAD8E71;
		m_sBox[3][45] = (LONG)0x6B93D5A0;m_sBox[0][46] = (LONG)0xD08ED1D0;m_sBox[1][46] = (LONG)0xAFC725E0;
		m_sBox[2][46] = (LONG)0x8E3C5B2F;
		m_sBox[3][46] = (LONG)0x8E7594B7;
		m_sBox[0][47] = (LONG)0x8FF6E2FB;
		m_sBox[1][47] = (LONG)0xF2122B64;
		m_sBox[2][47] = (LONG)0x8888B812;
		m_sBox[3][47] = (LONG)0x900DF01C;
		m_sBox[0][48] = (LONG)0x4FAD5EA0;
		m_sBox[1][48] = (LONG)0x688FC31C;
		m_sBox[2][48] = (LONG)0xD1CFF191;
		m_sBox[3][48] = (LONG)0xB3A8C1AD;
		m_sBox[0][49] = (LONG)0x2F2F2218;
		m_sBox[1][49] = (LONG)0xBE0E1777;
		m_sBox[2][49] = (LONG)0xEA752DFE;
		m_sBox[3][49] = (LONG)0x8B021FA1;
		m_sBox[0][50] = (LONG)0xE5A0CC0F;
		m_sBox[1][50] = (LONG)0xB56F74E8;
		m_sBox[2][50] = (LONG)0x18ACF3D6;
		m_sBox[3][50] = (LONG)0xCE89E299;
		m_sBox[0][51] = (LONG)0xB4A84FE0;
		m_sBox[1][51] = (LONG)0xFD13E0B7;
		m_sBox[2][51] = (LONG)0x7CC43B81;
		m_sBox[3][51] = (LONG)0xD2ADA8D9;
		m_sBox[0][52] = (LONG)0x165FA266;
		m_sBox[1][52] = (LONG)0x80957705;
		m_sBox[2][52] = (LONG)0x93CC7314;
		m_sBox[3][52] = (LONG)0x211A1477;
		m_sBox[0][53] = (LONG)0xE6AD2065;
		m_sBox[1][53] = (LONG)0x77B5FA86;
		m_sBox[2][53] = (LONG)0xC75442F5;
		m_sBox[3][53] = (LONG)0xFB9D35CF;
		m_sBox[0][54] = (LONG)0xEBCDAF0C;
		m_sBox[1][54] = (LONG)0x7B3E89A0;
		m_sBox[2][54] = (LONG)0xD6411BD3;
		m_sBox[3][54] = (LONG)0xAE1E7E49;
		m_sBox[0][55] = (LONG)0x250E2D;
		m_sBox[1][55] = (LONG)0x2071B35E;
		m_sBox[2][55] = (LONG)0x226800BB;
		m_sBox[3][55] = (LONG)0x57B8E0AF;
		m_sBox[0][56] = (LONG)0x2464369B;
		m_sBox[1][56] = (LONG)0xF009B91E;
		m_sBox[2][56] = (LONG)0x5563911D;
		m_sBox[3][56] = (LONG)0x59DFA6AA;
		m_sBox[0][57] = (LONG)0x78C14389;
		m_sBox[1][57] = (LONG)0xD95A537F;
		m_sBox[2][57] = (LONG)0x207D5BA2;
		m_sBox[3][57] = (LONG)0x2E5B9C5;
		m_sBox[0][58] = (LONG)0x83260376;
		m_sBox[1][58] = (LONG)0x6295CFA9;
		m_sBox[2][58] = (LONG)0x11C81968;
		m_sBox[3][58] = (LONG)0x4E734A41;
		m_sBox[0][59] = (LONG)0xB3472DCA;
		m_sBox[1][59] = (LONG)0x7B14A94A;
		m_sBox[2][59] = (LONG)0x1B510052;
		m_sBox[3][59] = (LONG)0x9A532915;
		m_sBox[0][60] = (LONG)0xD60F573F;
		m_sBox[1][60] = (LONG)0xBC9BC6E4;
		m_sBox[2][60] = (LONG)0x2B60A476;
		m_sBox[3][60] = (LONG)0x81E67400;
		m_sBox[0][61] = (LONG)0x8BA6FB5;
		m_sBox[1][61] = (LONG)0x571BE91F;
		m_sBox[2][61] = (LONG)0xF296EC6B;
		m_sBox[3][61] = (LONG)0x2A0DD915;
		m_sBox[0][62] = (LONG)0xB6636521;
		m_sBox[1][62] = (LONG)0xE7B9F9B6;
		m_sBox[2][62] = (LONG)0xFF34052E;
		m_sBox[3][62] = (LONG)0xC5855664;
		m_sBox[0][63] = (LONG)0x53B02D5D;
		m_sBox[1][63] = (LONG)0xA99F8FA1;
		m_sBox[2][63] = (LONG)0x8BA4799;
		m_sBox[3][63] = (LONG)0x6E85076A;
		m_sBox[0][64] = (LONG)0x4B7A70E9;
		m_sBox[1][64] = (LONG)0xB5B32944;
		m_sBox[2][64] = (LONG)0xDB75092E;
		m_sBox[3][64] = (LONG)0xC4192623;
		m_sBox[0][65] = (LONG)0xAD6EA6B0;
		m_sBox[1][65] = (LONG)0x49A7DF7D;
		m_sBox[2][65] = (LONG)0x9CEE60B8;
		m_sBox[3][65] = (LONG)0x8FEDB266;
		m_sBox[0][66] = (LONG)0xECAA8C71;
		m_sBox[1][66] = (LONG)0x699A17FF;
		m_sBox[2][66] = (LONG)0x5664526C;
		m_sBox[3][66] = (LONG)0xC2B19EE1;
		m_sBox[0][67] = (LONG)0x193602A5;
		m_sBox[1][67] = (LONG)0x75094C29;
		m_sBox[2][67] = (LONG)0xA0591340;
		m_sBox[3][67] = (LONG)0xE4183A3E;
		m_sBox[0][68] = (LONG)0x3F54989A;
		m_sBox[1][68] = (LONG)0x5B429D65;
		m_sBox[2][68] = (LONG)0x6B8FE4D6;
		m_sBox[3][68] = (LONG)0x99F73FD6;
		m_sBox[0][69] = (LONG)0xA1D29C07;
		m_sBox[1][69] = (LONG)0xEFE830F5;
		m_sBox[2][69] = (LONG)0x4D2D38E6;
		m_sBox[3][69] = (LONG)0xF0255DC1;
		m_sBox[0][70] = (LONG)0x4CDD2086;
		m_sBox[1][70] = (LONG)0x8470EB26;
		m_sBox[2][70] = (LONG)0x6382E9C6;
		m_sBox[3][70] = (LONG)0x21ECC5E;
		m_sBox[0][71] = (LONG)0x9686B3F;
		m_sBox[1][71] = (LONG)0x3EBAEFC9;
		m_sBox[2][71] = (LONG)0x3C971814;
		m_sBox[3][71] = (LONG)0x6B6A70A1;
		m_sBox[0][72] = (LONG)0x687F3584;
		m_sBox[1][72] = (LONG)0x52A0E286;
		m_sBox[2][72] = (LONG)0xB79C5305;
		m_sBox[3][72] = (LONG)0xAA500737;
		m_sBox[0][73] = (LONG)0x3E07841C;
		m_sBox[1][73] = (LONG)0x7FDEAE5C;
		m_sBox[2][73] = (LONG)0x8E7D44EC;
		m_sBox[3][73] = (LONG)0x5716F2B8;
		m_sBox[0][74] = (LONG)0xB03ADA37;
		m_sBox[1][74] = (LONG)0xF0500C0D;
		m_sBox[2][74] = (LONG)0xF01C1F04;
		m_sBox[3][74] = (LONG)0x200B3FF;
		m_sBox[0][75] = (LONG)0xAE0CF51A;
		m_sBox[1][75] = (LONG)0x3CB574B2;
		m_sBox[2][75] = (LONG)0x25837A58;
		m_sBox[3][75] = (LONG)0xDC0921BD;
		m_sBox[0][76] = (LONG)0xD19113F9;
		m_sBox[1][76] = (LONG)0x7CA92FF6;
		m_sBox[2][76] = (LONG)0x94324773;
		m_sBox[3][76] = (LONG)0x22F54701;
		m_sBox[0][77] = (LONG)0x3AE5E581;
		m_sBox[1][77] = (LONG)0x37C2DADC;
		m_sBox[2][77] = (LONG)0xC8B57634;
		m_sBox[3][77] = (LONG)0x9AF3DDA7;
		m_sBox[0][78] = (LONG)0xA9446146;
		m_sBox[1][78] = (LONG)0xFD0030E;
		m_sBox[2][78] = (LONG)0xECC8C73E;
		m_sBox[3][78] = (LONG)0xA4751E41;
		m_sBox[0][79] = (LONG)0xE238CD99;
		m_sBox[1][79] = (LONG)0x3BEA0E2F;
		m_sBox[2][79] = (LONG)0x3280BBA1;
		m_sBox[3][79] = (LONG)0x183EB331;
		m_sBox[0][80] = (LONG)0x4E548B38;
		m_sBox[1][80] = (LONG)0x4F6DB908;
		m_sBox[2][80] = (LONG)0x6F420D03;
		m_sBox[3][80] = (LONG)0xF60A04BF;
		m_sBox[0][81] = (LONG)0x2CB81290;
		m_sBox[1][81] = (LONG)0x24977C79;
		m_sBox[2][81] = (LONG)0x5679B072;
		m_sBox[3][81] = (LONG)0xBCAF89AF;
		m_sBox[0][82] = (LONG)0xDE9A771F;
		m_sBox[1][82] = (LONG)0xD9930810;
		m_sBox[2][82] = (LONG)0xB38BAE12;
		m_sBox[3][82] = (LONG)0xDCCF3F2E;
		m_sBox[0][83] = (LONG)0x5512721F;
		m_sBox[1][83] = (LONG)0x2E6B7124;
		m_sBox[2][83] = (LONG)0x501ADDE6;
		m_sBox[3][83] = (LONG)0x9F84CD87;
		m_sBox[0][84] = (LONG)0x7A584718;
		m_sBox[1][84] = (LONG)0x7408DA17;
		m_sBox[2][84] = (LONG)0xBC9F9ABC;
		m_sBox[3][84] = (LONG)0xE94B7D8C;
		m_sBox[0][85] = (LONG)0xEC7AEC3A;
		m_sBox[1][85] = (LONG)0xDB851DFA;
		m_sBox[2][85] = (LONG)0x63094366;
		m_sBox[3][85] = (LONG)0xC464C3D2;
		m_sBox[0][86] = (LONG)0xEF1C1847;
		m_sBox[1][86] = (LONG)0x3215D908;
		m_sBox[2][86] = (LONG)0xDD433B37;
		m_sBox[3][86] = (LONG)0x24C2BA16;
		m_sBox[0][87] = (LONG)0x12A14D43;
		m_sBox[1][87] = (LONG)0x2A65C451;
		m_sBox[2][87] = (LONG)0x50940002;
		m_sBox[3][87] = (LONG)0x133AE4DD;
		m_sBox[0][88] = (LONG)0x71DFF89E;
		m_sBox[1][88] = (LONG)0x10314E55;
		m_sBox[2][88] = (LONG)0x81AC77D6;
		m_sBox[3][88] = (LONG)0x5F11199B;
		m_sBox[0][89] = (LONG)0x43556F1;
		m_sBox[1][89] = (LONG)0xD7A3C76B;
		m_sBox[2][89] = (LONG)0x3C11183B;
		m_sBox[3][89] = (LONG)0x5924A509;
		m_sBox[0][90] = (LONG)0xF28FE6ED;
		m_sBox[1][90] = (LONG)0x97F1FBFA;
		m_sBox[2][90] = (LONG)0x9EBABF2C;
		m_sBox[3][90] = (LONG)0x1E153C6E;
		m_sBox[0][91] = (LONG)0x86E34570;
		m_sBox[1][91] = (LONG)0xEAE96FB1;
		m_sBox[2][91] = (LONG)0x860E5E0A;
		m_sBox[3][91] = (LONG)0x5A3E2AB3;
		m_sBox[0][92] = (LONG)0x771FE71C;
		m_sBox[1][92] = (LONG)0x4E3D06FA;
		m_sBox[2][92] = (LONG)0x2965DCB9;
		m_sBox[3][92] = (LONG)0x99E71D0F;
		m_sBox[0][93] = (LONG)0x803E89D6;
		m_sBox[1][93] = (LONG)0x5266C825;
		m_sBox[2][93] = (LONG)0x2E4CC978;
		m_sBox[3][93] = (LONG)0x9C10B36A;
		m_sBox[0][94] = (LONG)0xC6150EBA;
		m_sBox[1][94] = (LONG)0x94E2EA78;
		m_sBox[2][94] = (LONG)0xA5FC3C53;
		m_sBox[3][94] = (LONG)0x1E0A2DF4;
		m_sBox[0][95] = (LONG)0xF2F74EA7;
		m_sBox[1][95] = (LONG)0x361D2B3D;
		m_sBox[2][95] = (LONG)0x1939260F;
		m_sBox[3][95] = (LONG)0x19C27960;
		m_sBox[0][96] = (LONG)0x5223A708;
		m_sBox[1][96] = (LONG)0xF71312B6;
		m_sBox[2][96] = (LONG)0xEBADFE6E;
		m_sBox[3][96] = (LONG)0xEAC31F66;
		m_sBox[0][97] = (LONG)0xE3BC4595;
		m_sBox[1][97] = (LONG)0xA67BC883;
		m_sBox[2][97] = (LONG)0xB17F37D1;
		m_sBox[3][97] = (LONG)0x18CFF28;
		m_sBox[0][98] = (LONG)0xC332DDEF;
		m_sBox[1][98] = (LONG)0xBE6C5AA5;
		m_sBox[2][98] = (LONG)0x65582185;
		m_sBox[3][98] = (LONG)0x68AB9802;
		m_sBox[0][99] = (LONG)0xEECEA50F;
		m_sBox[1][99] = (LONG)0xDB2F953B;
		m_sBox[2][99] = (LONG)0x2AEF7DAD;
		m_sBox[3][99] = (LONG)0x5B6E2F84;
		m_sBox[0][100] = (LONG)0x1521B628;
		m_sBox[1][100] = (LONG)0x29076170;
		m_sBox[2][100] = (LONG)0xECDD4775;
		m_sBox[3][100] = (LONG)0x619F1510;
		m_sBox[0][101] = (LONG)0x13CCA830;
		m_sBox[1][101] = (LONG)0xEB61BD96;
		m_sBox[2][101] = (LONG)0x334FE1E;
		m_sBox[3][101] = (LONG)0xAA0363CF;
		m_sBox[0][102] = (LONG)0xB5735C90;
		m_sBox[1][102] = (LONG)0x4C70A239;
		m_sBox[2][102] = (LONG)0xD59E9E0B;
		m_sBox[3][102] = (LONG)0xCBAADE14;
		m_sBox[0][103] = (LONG)0xEECC86BC;
		m_sBox[1][103] = (LONG)0x60622CA7;
		m_sBox[2][103] = (LONG)0x9CAB5CAB;
		m_sBox[3][103] = (LONG)0xB2F3846E;
		m_sBox[0][104] = (LONG)0x648B1EAF;
		m_sBox[1][104] = (LONG)0x19BDF0CA;
		m_sBox[2][104] = (LONG)0xA02369B9;
		m_sBox[3][104] = (LONG)0x655ABB50;
		m_sBox[0][105] = (LONG)0x40685A32;
		m_sBox[1][105] = (LONG)0x3C2AB4B3;
		m_sBox[2][105] = (LONG)0x319EE9D5;
		m_sBox[3][105] = (LONG)0xC021B8F7;
		m_sBox[0][106] = (LONG)0x9B540B19;
		m_sBox[1][106] = (LONG)0x875FA099;
		m_sBox[2][106] = (LONG)0x95F7997E;
		m_sBox[3][106] = (LONG)0x623D7DA8;
		m_sBox[0][107] = (LONG)0xF837889A;
		m_sBox[1][107] = (LONG)0x97E32D77;
		m_sBox[2][107] = (LONG)0x11ED935F;
		m_sBox[3][107] = (LONG)0x16681281;
		m_sBox[0][108] = (LONG)0xE358829;
		m_sBox[1][108] = (LONG)0xC7E61FD6;
		m_sBox[2][108] = (LONG)0x96DEDFA1;
		m_sBox[3][108] = (LONG)0x7858BA99;
		m_sBox[0][109] = (LONG)0x57F584A5;
		m_sBox[1][109] = (LONG)0x1B227263;
		m_sBox[2][109] = (LONG)0x9B83C3FF;
		m_sBox[3][109] = (LONG)0x1AC24696;
		m_sBox[0][110] = (LONG)0xCDB30AEB;
		m_sBox[1][110] = (LONG)0x532E3054;
		m_sBox[2][110] = (LONG)0x8FD948E4;
		m_sBox[3][110] = (LONG)0x6DBC3128;
		m_sBox[0][111] = (LONG)0x58EBF2EF;
		m_sBox[1][111] = (LONG)0x34C6FFEA;
		m_sBox[2][111] = (LONG)0xFE28ED61;
		m_sBox[3][111] = (LONG)0xEE7C3C73;
		m_sBox[0][112] = (LONG)0x5D4A14D9;
		m_sBox[1][112] = (LONG)0xE864B7E3;
		m_sBox[2][112] = (LONG)0x42105D14;
		m_sBox[3][112] = (LONG)0x203E13E0;
		m_sBox[0][113] = (LONG)0x45EEE2B6;
		m_sBox[1][113] = (LONG)0xA3AAABEA;
		m_sBox[2][113] = (LONG)0xDB6C4F15;
		m_sBox[3][113] = (LONG)0xFACB4FD0;
		m_sBox[0][114] = (LONG)0xC742F442;
		m_sBox[1][114] = (LONG)0xEF6ABBB5;
		m_sBox[2][114] = (LONG)0x654F3B1D;
		m_sBox[3][114] = (LONG)0x41CD2105;
		m_sBox[0][115] = (LONG)0xD81E799E;
		m_sBox[1][115] = (LONG)0x86854DC7;
		m_sBox[2][115] = (LONG)0xE44B476A;
		m_sBox[3][115] = (LONG)0x3D816250;
		m_sBox[0][116] = (LONG)0xCF62A1F2;
		m_sBox[1][116] = (LONG)0x5B8D2646;
		m_sBox[2][116] = (LONG)0xFC8883A0;
		m_sBox[3][116] = (LONG)0xC1C7B6A3;
		m_sBox[0][117] = (LONG)0x7F1524C3;
		m_sBox[1][117] = (LONG)0x69CB7492;
		m_sBox[2][117] = (LONG)0x47848A0B;
		m_sBox[3][117] = (LONG)0x5692B285;
		m_sBox[0][118] = (LONG)0x95BBF00;
		m_sBox[1][118] = (LONG)0xAD19489D;
		m_sBox[2][118] = (LONG)0x1462B174;
		m_sBox[3][118] = (LONG)0x23820E00;
		m_sBox[0][119] = (LONG)0x58428D2A;
		m_sBox[1][119] = (LONG)0xC55F5EA;
		m_sBox[2][119] = (LONG)0x1DADF43E;
		m_sBox[3][119] = (LONG)0x233F7061;
		m_sBox[0][120] = (LONG)0x3372F092;
		m_sBox[1][120] = (LONG)0x8D937E41;
		m_sBox[2][120] = (LONG)0xD65FECF1;
		m_sBox[3][120] = (LONG)0x6C223BDB;
		m_sBox[0][121] = (LONG)0x7CDE3759;
		m_sBox[1][121] = (LONG)0xCBEE7460;
		m_sBox[2][121] = (LONG)0x4085F2A7;
		m_sBox[3][121] = (LONG)0xCE77326E;
		m_sBox[0][122] = (LONG)0xA6078084;
		m_sBox[1][122] = (LONG)0x19F8509E;
		m_sBox[2][122] = (LONG)0xE8EFD855;
		m_sBox[3][122] = (LONG)0x61D99735;
		m_sBox[0][123] = (LONG)0xA969A7AA;
		m_sBox[1][123] = (LONG)0xC50C06C2;
		m_sBox[2][123] = (LONG)0x5A04ABFC;
		m_sBox[3][123] = (LONG)0x800BCADC;
		m_sBox[0][124] = (LONG)0x9E447A2E;
		m_sBox[1][124] = (LONG)0xC3453484;
		m_sBox[2][124] = (LONG)0xFDD56705;
		m_sBox[3][124] = (LONG)0xE1E9EC9;
		m_sBox[0][125] = (LONG)0xDB73DBD3;
		m_sBox[1][125] = (LONG)0x105588CD;
		m_sBox[2][125] = (LONG)0x675FDA79;
		m_sBox[3][125] = (LONG)0xE3674340;
		m_sBox[0][126] = (LONG)0xC5C43465;
		m_sBox[1][126] = (LONG)0x713E38D8;
		m_sBox[2][126] = (LONG)0x3D28F89E;
		m_sBox[3][126] = (LONG)0xF16DFF20;
		m_sBox[0][127] = (LONG)0x153E21E7;
		m_sBox[1][127] = (LONG)0x8FB03D4A;
		m_sBox[2][127] = (LONG)0xE6E39F2B;
		m_sBox[3][127] = (LONG)0xDB83ADF7;
		m_sBox[0][128] = (LONG)0xE93D5A68;
		m_sBox[1][128] = (LONG)0x948140F7;
		m_sBox[2][128] = (LONG)0xF64C261C;
		m_sBox[3][128] = (LONG)0x94692934;
		m_sBox[0][129] = (LONG)0x411520F7;
		m_sBox[1][129] = (LONG)0x7602D4F7;
		m_sBox[2][129] = (LONG)0xBCF46B2E;
		m_sBox[3][129] = (LONG)0xD4A20068;
		m_sBox[0][130] = (LONG)0xD4082471;
		m_sBox[1][130] = (LONG)0x3320F46A;
		m_sBox[2][130] = (LONG)0x43B7D4B7;
		m_sBox[3][130] = (LONG)0x500061AF;
		m_sBox[0][131] = (LONG)0x1E39F62E;
		m_sBox[1][131] = (LONG)0x97244546;
		m_sBox[2][131] = (LONG)0x14214F74;
		m_sBox[3][131] = (LONG)0xBF8B8840;
		m_sBox[0][132] = (LONG)0x4D95FC1D;
		m_sBox[1][132] = (LONG)0x96B591AF;
		m_sBox[2][132] = (LONG)0x70F4DDD3;
		m_sBox[3][132] = (LONG)0x66A02F45;
		m_sBox[0][133] = (LONG)0xBFBC09EC;
		m_sBox[1][133] = (LONG)0x3BD9785;
		m_sBox[2][133] = (LONG)0x7FAC6DD0;
		m_sBox[3][133] = (LONG)0x31CB8504;
		m_sBox[0][134] = (LONG)0x96EB27B3;
		m_sBox[1][134] = (LONG)0x55FD3941;
		m_sBox[2][134] = (LONG)0xDA2547E6;
		m_sBox[3][134] = (LONG)0xABCA0A9A;
		m_sBox[0][135] = (LONG)0x28507825;
		m_sBox[1][135] = (LONG)0x530429F4;
		m_sBox[2][135] = (LONG)0xA2C86DA;
		m_sBox[3][135] = (LONG)0xE9B66DFB;
		m_sBox[0][136] = (LONG)0x68DC1462;
		m_sBox[1][136] = (LONG)0xD7486900;
		m_sBox[2][136] = (LONG)0x680EC0A4;
		m_sBox[3][136] = (LONG)0x27A18DEE;
		m_sBox[0][137] = (LONG)0x4F3FFEA2;
		m_sBox[1][137] = (LONG)0xE887AD8C;
		m_sBox[2][137] = (LONG)0xB58CE006;
		m_sBox[3][137] = (LONG)0x7AF4D6B6;
		m_sBox[0][138] = (LONG)0xAACE1E7C;
		m_sBox[1][138] = (LONG)0xD3375FEC;
		m_sBox[2][138] = (LONG)0xCE78A399;
		m_sBox[3][138] = (LONG)0x406B2A42;
		m_sBox[0][139] = (LONG)0x20FE9E35;
		m_sBox[1][139] = (LONG)0xD9F385B9;
		m_sBox[2][139] = (LONG)0xEE39D7AB;
		m_sBox[3][139] = (LONG)0x3B124E8B;
		m_sBox[0][140] = (LONG)0x1DC9FAF7;
		m_sBox[1][140] = (LONG)0x4B6D1856;
		m_sBox[2][140] = (LONG)0x26A36631;
		m_sBox[3][140] = (LONG)0xEAE397B2;
		m_sBox[0][141] = (LONG)0x3A6EFA74;
		m_sBox[1][141] = (LONG)0xDD5B4332;
		m_sBox[2][141] = (LONG)0x6841E7F7;
		m_sBox[3][141] = (LONG)0xCA7820FB;
		m_sBox[0][142] = (LONG)0xFB0AF54E;
		m_sBox[1][142] = (LONG)0xD8FEB397;
		m_sBox[2][142] = (LONG)0x454056AC;
		m_sBox[3][142] = (LONG)0xBA489527;
		m_sBox[0][143] = (LONG)0x55533A3A;
		m_sBox[1][143] = (LONG)0x20838D87;
		m_sBox[2][143] = (LONG)0xFE6BA9B7;
		m_sBox[3][143] = (LONG)0xD096954B;
		m_sBox[0][144] = (LONG)0x55A867BC;
		m_sBox[1][144] = (LONG)0xA1159A58;
		m_sBox[2][144] = (LONG)0xCCA92963;
		m_sBox[3][144] = (LONG)0x99E1DB33;
		m_sBox[0][145] = (LONG)0xA62A4A56;
		m_sBox[1][145] = (LONG)0x3F3125F9;
		m_sBox[2][145] = (LONG)0x5EF47E1C;
		m_sBox[3][145] = (LONG)0x9029317C;
		m_sBox[0][146] = (LONG)0xFDF8E802;
		m_sBox[1][146] = (LONG)0x4272F70;
		m_sBox[2][146] = (LONG)0x80BB155C;
		m_sBox[3][146] = (LONG)0x5282CE3;
		m_sBox[0][147] = (LONG)0x95C11548;
		m_sBox[1][147] = (LONG)0xE4C66D22;
		m_sBox[2][147] = (LONG)0x48C1133F;
		m_sBox[3][147] = (LONG)0xC70F86DC;
		m_sBox[0][148] = (LONG)0x7F9C9EE;
		m_sBox[1][148] = (LONG)0x41041F0F;
		m_sBox[2][148] = (LONG)0x404779A4;
		m_sBox[3][148] = (LONG)0x5D886E17;
		m_sBox[0][149] = (LONG)0x325F51EB;
		m_sBox[1][149] = (LONG)0xD59BC0D1;
		m_sBox[2][149] = (LONG)0xF2BCC18F;
		m_sBox[3][149] = (LONG)0x41113564;
		m_sBox[0][150] = (LONG)0x257B7834;
		m_sBox[1][150] = (LONG)0x602A9C60;
		m_sBox[2][150] = (LONG)0xDFF8E8A3;
		m_sBox[3][150] = (LONG)0x1F636C1B;
		m_sBox[0][151] = (LONG)0xE12B4C2;
		m_sBox[1][151] = (LONG)0x2E1329E;
		m_sBox[2][151] = (LONG)0xAF664FD1;
		m_sBox[3][151] = (LONG)0xCAD18115;
		m_sBox[0][152] = (LONG)0x6B2395E0;
		m_sBox[1][152] = (LONG)0x333E92E1;
		m_sBox[2][152] = (LONG)0x3B240B62;
		m_sBox[3][152] = (LONG)0xEEBEB922;
		m_sBox[0][153] = (LONG)0x85B2A20E;
		m_sBox[1][153] = (LONG)0xE6BA0D99;
		m_sBox[2][153] = (LONG)0xDE720C8C;
		m_sBox[3][153] = (LONG)0x2DA2F728;
		m_sBox[0][154] = (LONG)0xD0127845;
		m_sBox[1][154] = (LONG)0x95B794FD;
		m_sBox[2][154] = (LONG)0x647D0862;
		m_sBox[3][154] = (LONG)0xE7CCF5F0;
		m_sBox[0][155] = (LONG)0x5449A36F;
		m_sBox[1][155] = (LONG)0x877D48FA;
		m_sBox[2][155] = (LONG)0xC39DFD27;
		m_sBox[3][155] = (LONG)0xF33E8D1E;
		m_sBox[0][156] = (LONG)0xA476341;
		m_sBox[1][156] = (LONG)0x992EFF74;
		m_sBox[2][156] = (LONG)0x3A6F6EAB;
		m_sBox[3][156] = (LONG)0xF4F8FD37;
		m_sBox[0][157] = (LONG)0xA812DC60;
		m_sBox[1][157] = (LONG)0xA1EBDDF8;
		m_sBox[2][157] = (LONG)0x991BE14C;
		m_sBox[3][157] = (LONG)0xDB6E6B0D;
		m_sBox[0][158] = (LONG)0xC67B5510;
		m_sBox[1][158] = (LONG)0x6D672C37;
		m_sBox[2][158] = (LONG)0x2765D43B;
		m_sBox[3][158] = (LONG)0xDCD0E804;
		m_sBox[0][159] = (LONG)0xF1290DC7;
		m_sBox[1][159] = (LONG)0xCC00FFA3;
		m_sBox[2][159] = (LONG)0xB5390F92;
		m_sBox[3][159] = (LONG)0x690FED0B;
		m_sBox[0][160] = (LONG)0x667B9FFB;
		m_sBox[1][160] = (LONG)0xCEDB7D9C;
		m_sBox[2][160] = (LONG)0xA091CF0B;
		m_sBox[3][160] = (LONG)0xD9155EA3;
		m_sBox[0][161] = (LONG)0xBB132F88;
		m_sBox[1][161] = (LONG)0x515BAD24;
		m_sBox[2][161] = (LONG)0x7B9479BF;
		m_sBox[3][161] = (LONG)0x763BD6EB;
		m_sBox[0][162] = (LONG)0x37392EB3;
		m_sBox[1][162] = (LONG)0xCC115979;
		m_sBox[2][162] = (LONG)0x8026E297;
		m_sBox[3][162] = (LONG)0xF42E312D;
		m_sBox[0][163] = (LONG)0x6842ADA7;
		m_sBox[1][163] = (LONG)0xC66A2B3B;
		m_sBox[2][163] = (LONG)0x12754CCC;
		m_sBox[3][163] = (LONG)0x782EF11C;
		m_sBox[0][164] = (LONG)0x6A124237;
		m_sBox[1][164] = (LONG)0xB79251E7;
		m_sBox[2][164] = (LONG)0x6A1BBE6;
		m_sBox[3][164] = (LONG)0x4BFB6350;
		m_sBox[0][165] = (LONG)0x1A6B1018;
		m_sBox[1][165] = (LONG)0x11CAEDFA;
		m_sBox[2][165] = (LONG)0x3D25BDD8;
		m_sBox[3][165] = (LONG)0xE2E1C3C9;
		m_sBox[0][166] = (LONG)0x44421659;
		m_sBox[1][166] = (LONG)0xA121386;
		m_sBox[2][166] = (LONG)0xD90CEC6E;
		m_sBox[3][166] = (LONG)0xD5ABEA2A;
		m_sBox[0][167] = (LONG)0x64AF674E;
		m_sBox[1][167] = (LONG)0xDA86A85F;
		m_sBox[2][167] = (LONG)0xBEBFE988;
		m_sBox[3][167] = (LONG)0x64E4C3FE;
		m_sBox[0][168] = (LONG)0x9DBC8057;
		m_sBox[1][168] = (LONG)0xF0F7C086;
		m_sBox[2][168] = (LONG)0x60787BF8;
		m_sBox[3][168] = (LONG)0x6003604D;
		m_sBox[0][169] = (LONG)0xD1FD8346;
		m_sBox[1][169] = (LONG)0xF6381FB0;
		m_sBox[2][169] = (LONG)0x7745AE04;
		m_sBox[3][169] = (LONG)0xD736FCCC;
		m_sBox[0][170] = (LONG)0x83426B33;
		m_sBox[1][170] = (LONG)0xF01EAB71;
		m_sBox[2][170] = (LONG)0xB0804187;
		m_sBox[3][170] = (LONG)0x3C005E5F;
		m_sBox[0][171] = (LONG)0x77A057BE;
		m_sBox[1][171] = (LONG)0xBDE8AE24;
		m_sBox[2][171] = (LONG)0x55464299;
		m_sBox[3][171] = (LONG)0xBF582E61;
		m_sBox[0][172] = (LONG)0x4E58F48F;
		m_sBox[1][172] = (LONG)0xF2DDFDA2;
		m_sBox[2][172] = (LONG)0xF474EF38;
		m_sBox[3][172] = (LONG)0x8789BDC2;
		m_sBox[0][173] = (LONG)0x5366F9C3;
		m_sBox[1][173] = (LONG)0xC8B38E74;
		m_sBox[2][173] = (LONG)0xB475F255;
		m_sBox[3][173] = (LONG)0x46FCD9B9;
		m_sBox[0][174] = (LONG)0x7AEB2661;
		m_sBox[1][174] = (LONG)0x8B1DDF84;
		m_sBox[2][174] = (LONG)0x846A0E79;
		m_sBox[3][174] = (LONG)0x915F95E2;
		m_sBox[0][175] = (LONG)0x466E598E;
		m_sBox[1][175] = (LONG)0x20B45770;
		m_sBox[2][175] = (LONG)0x8CD55591;
		m_sBox[3][175] = (LONG)0xC902DE4C;
		m_sBox[0][176] = (LONG)0xB90BACE1;
		m_sBox[1][176] = (LONG)0xBB8205D0;
		m_sBox[2][176] = (LONG)0x11A86248;
		m_sBox[3][176] = (LONG)0x7574A99E;
		m_sBox[0][177] = (LONG)0xB77F19B6;
		m_sBox[1][177] = (LONG)0xE0A9DC09;
		m_sBox[2][177] = (LONG)0x662D09A1;
		m_sBox[3][177] = (LONG)0xC4324633;
		m_sBox[0][178] = (LONG)0xE85A1F02;
		m_sBox[1][178] = (LONG)0x9F0BE8C;
		m_sBox[2][178] = (LONG)0x4A99A025;
		m_sBox[3][178] = (LONG)0x1D6EFE10;
		m_sBox[0][179] = (LONG)0x1AB93D1D;
		m_sBox[1][179] = (LONG)0xBA5A4DF;
		m_sBox[2][179] = (LONG)0xA186F20F;
		m_sBox[3][179] = (LONG)0x2868F169;
		m_sBox[0][180] = (LONG)0xDCB7DA83;
		m_sBox[1][180] = (LONG)0x573906FE;
		m_sBox[2][180] = (LONG)0xA1E2CE9B;
		m_sBox[3][180] = (LONG)0x4FCD7F52;
		m_sBox[0][181] = (LONG)0x50115E01;
		m_sBox[1][181] = (LONG)0xA70683FA;
		m_sBox[2][181] = (LONG)0xA002B5C4;
		m_sBox[3][181] = (LONG)0xDE6D027;
		m_sBox[0][182] = (LONG)0x9AF88C27;
		m_sBox[1][182] = (LONG)0x773F8641;
		m_sBox[2][182] = (LONG)0xC3604C06;
		m_sBox[3][182] = (LONG)0x61A806B5;
		m_sBox[0][183] = (LONG)0xF0177A28;
		m_sBox[1][183] = (LONG)0xC0F586E0;
		m_sBox[2][183] = (LONG)0x6058AA;
		m_sBox[3][183] = (LONG)0x30DC7D62;
		m_sBox[0][184] = (LONG)0x11E69ED7;
		m_sBox[1][184] = (LONG)0x2338EA63;
		m_sBox[2][184] = (LONG)0x53C2DD94;
		m_sBox[3][184] = (LONG)0xC2C21634;
		m_sBox[0][185] = (LONG)0xBBCBEE56;
		m_sBox[1][185] = (LONG)0x90BCB6DE;
		m_sBox[2][185] = (LONG)0xEBFC7DA1;
		m_sBox[3][185] = (LONG)0xCE591D76;
		m_sBox[0][186] = (LONG)0x6F05E409;
		m_sBox[1][186] = (LONG)0x4B7C0188;
		m_sBox[2][186] = (LONG)0x39720A3D;
		m_sBox[3][186] = (LONG)0x7C927C24;
		m_sBox[0][187] = (LONG)0x86E3725F;
		m_sBox[1][187] = (LONG)0x724D9DB9;
		m_sBox[2][187] = (LONG)0x1AC15BB4;
		m_sBox[3][187] = (LONG)0xD39EB8FC;
		m_sBox[0][188] = (LONG)0xED545578;
		m_sBox[1][188] = (LONG)0x8FCA5B5;
		m_sBox[2][188] = (LONG)0xD83D7CD3;
		m_sBox[3][188] = (LONG)0x4DAD0FC4;
		m_sBox[0][189] = (LONG)0x1E50EF5E;
		m_sBox[1][189] = (LONG)0xB161E6F8;
		m_sBox[2][189] = (LONG)0xA28514D9;
		m_sBox[3][189] = (LONG)0x6C51133C;
		m_sBox[0][190] = (LONG)0x6FD5C7E7;
		m_sBox[1][190] = (LONG)0x56E14EC4;
		m_sBox[2][190] = (LONG)0x362ABFCE;
		m_sBox[3][190] = (LONG)0xDDC6C837;
		m_sBox[0][191] = (LONG)0xD79A3234;
		m_sBox[1][191] = (LONG)0x92638212;
		m_sBox[2][191] = (LONG)0x670EFA8E;
		m_sBox[3][191] = (LONG)0x406000E0;
		m_sBox[0][192] = (LONG)0x3A39CE37;
		m_sBox[1][192] = (LONG)0xD3FAF5CF;
		m_sBox[2][192] = (LONG)0xABC27737;
		m_sBox[3][192] = (LONG)0x5AC52D1B;
		m_sBox[0][193] = (LONG)0x5CB0679E;
		m_sBox[1][193] = (LONG)0x4FA33742;
		m_sBox[2][193] = (LONG)0xD3822740;
		m_sBox[3][193] = (LONG)0x99BC9BBE;
		m_sBox[0][194] = (LONG)0xD5118E9D;
		m_sBox[1][194] = (LONG)0xBF0F7315;
		m_sBox[2][194] = (LONG)0xD62D1C7E;
		m_sBox[3][194] = (LONG)0xC700C47B;
		m_sBox[0][195] = (LONG)0xB78C1B6B;
		m_sBox[1][195] = (LONG)0x21A19045;
		m_sBox[2][195] = (LONG)0xB26EB1BE;
		m_sBox[3][195] = (LONG)0x6A366EB4;
		m_sBox[0][196] = (LONG)0x5748AB2F;
		m_sBox[1][196] = (LONG)0xBC946E79;
		m_sBox[2][196] = (LONG)0xC6A376D2;
		m_sBox[3][196] = (LONG)0x6549C2C8;
		m_sBox[0][197] = (LONG)0x530FF8EE;
		m_sBox[1][197] = (LONG)0x468DDE7D;
		m_sBox[2][197] = (LONG)0xD5730A1D;
		m_sBox[3][197] = (LONG)0x4CD04DC6;
		m_sBox[0][198] = (LONG)0x2939BBDB;
		m_sBox[1][198] = (LONG)0xA9BA4650;
		m_sBox[2][198] = (LONG)0xAC9526E8;
		m_sBox[3][198] = (LONG)0xBE5EE304;
		m_sBox[0][199] = (LONG)0xA1FAD5F0;
		m_sBox[1][199] = (LONG)0x6A2D519A;
		m_sBox[2][199] = (LONG)0x63EF8CE2;
		m_sBox[3][199] = (LONG)0x9A86EE22;
		m_sBox[0][200] = (LONG)0xC089C2B8;
		m_sBox[1][200] = (LONG)0x43242EF6;
		m_sBox[2][200] = (LONG)0xA51E03AA;
		m_sBox[3][200] = (LONG)0x9CF2D0A4;
		m_sBox[0][201] = (LONG)0x83C061BA;
		m_sBox[1][201] = (LONG)0x9BE96A4D;
		m_sBox[2][201] = (LONG)0x8FE51550;
		m_sBox[3][201] = (LONG)0xBA645BD6;
		m_sBox[0][202] = (LONG)0x2826A2F9;
		m_sBox[1][202] = (LONG)0xA73A3AE1;
		m_sBox[2][202] = (LONG)0x4BA99586;
		m_sBox[3][202] = (LONG)0xEF5562E9;
		m_sBox[0][203] = (LONG)0xC72FEFD3;
		m_sBox[1][203] = (LONG)0xF752F7DA;
		m_sBox[2][203] = (LONG)0x3F046F69;
		m_sBox[3][203] = (LONG)0x77FA0A59;
		m_sBox[0][204] = (LONG)0x80E4A915;
		m_sBox[1][204] = (LONG)0x87B08601;
		m_sBox[2][204] = (LONG)0x9B09E6AD;
		m_sBox[3][204] = (LONG)0x3B3EE593;
		m_sBox[0][205] = (LONG)0xE990FD5A;
		m_sBox[1][205] = (LONG)0x9E34D797;
		m_sBox[2][205] = (LONG)0x2CF0B7D9;
		m_sBox[3][205] = (LONG)0x22B8B51;
		m_sBox[0][206] = (LONG)0x96D5AC3A;
		m_sBox[1][206] = (LONG)0x17DA67D;
		m_sBox[2][206] = (LONG)0xD1CF3ED6;
		m_sBox[3][206] = (LONG)0x7C7D2D28;
		m_sBox[0][207] = (LONG)0x1F9F25CF;
		m_sBox[1][207] = (LONG)0xADF2B89B;
		m_sBox[2][207] = (LONG)0x5AD6B472;
		m_sBox[3][207] = (LONG)0x5A88F54C;
		m_sBox[0][208] = (LONG)0xE029AC71;
		m_sBox[1][208] = (LONG)0xE019A5E6;
		m_sBox[2][208] = (LONG)0x47B0ACFD;
		m_sBox[3][208] = (LONG)0xED93FA9B;
		m_sBox[0][209] = (LONG)0xE8D3C48D;
		m_sBox[1][209] = (LONG)0x283B57CC;
		m_sBox[2][209] = (LONG)0xF8D56629;
		m_sBox[3][209] = (LONG)0x79132E28;
		m_sBox[0][210] = (LONG)0x785F0191;
		m_sBox[1][210] = (LONG)0xED756055;
		m_sBox[2][210] = (LONG)0xF7960E44;
		m_sBox[3][210] = (LONG)0xE3D35E8C;
		m_sBox[0][211] = (LONG)0x15056DD4;
		m_sBox[1][211] = (LONG)0x88F46DBA;
		m_sBox[2][211] = (LONG)0x3A16125;
		m_sBox[3][211] = (LONG)0x564F0BD;
		m_sBox[0][212] = (LONG)0xC3EB9E15;
		m_sBox[1][212] = (LONG)0x3C9057A2;
		m_sBox[2][212] = (LONG)0x97271AEC;
		m_sBox[3][212] = (LONG)0xA93A072A;
		m_sBox[0][213] = (LONG)0x1B3F6D9B;
		m_sBox[1][213] = (LONG)0x1E6321F5;
		m_sBox[2][213] = (LONG)0xF59C66FB;
		m_sBox[3][213] = (LONG)0x26DCF319;
		m_sBox[0][214] = (LONG)0x7533D928;
		m_sBox[1][214] = (LONG)0xB155FDF5;
		m_sBox[2][214] = (LONG)0x3563482;
		m_sBox[3][214] = (LONG)0x8ABA3CBB;
		m_sBox[0][215] = (LONG)0x28517711;
		m_sBox[1][215] = (LONG)0xC20AD9F8;
		m_sBox[2][215] = (LONG)0xABCC5167;
		m_sBox[3][215] = (LONG)0xCCAD925F;
		m_sBox[0][216] = (LONG)0x4DE81751;
		m_sBox[1][216] = (LONG)0x3830DC8E;
		m_sBox[2][216] = (LONG)0x379D5862;
		m_sBox[3][216] = (LONG)0x9320F991;
		m_sBox[0][217] = (LONG)0xEA7A90C2;
		m_sBox[1][217] = (LONG)0xFB3E7BCE;
		m_sBox[2][217] = (LONG)0x5121CE64;
		m_sBox[3][217] = (LONG)0x774FBE32;
		m_sBox[0][218] = (LONG)0xA8B6E37E;
		m_sBox[1][218] = (LONG)0xC3293D46;
		m_sBox[2][218] = (LONG)0x48DE5369;
		m_sBox[3][218] = (LONG)0x6413E680;
		m_sBox[0][219] = (LONG)0xA2AE0810;
		m_sBox[1][219] = (LONG)0xDD6DB224;
		m_sBox[2][219] = (LONG)0x69852DFD;
		m_sBox[3][219] = (LONG)0x9072166;
		m_sBox[0][220] = (LONG)0xB39A460A;
		m_sBox[1][220] = (LONG)0x6445C0DD;
		m_sBox[2][220] = (LONG)0x586CDECF;
		m_sBox[3][220] = (LONG)0x1C20C8AE;
		m_sBox[0][221] = (LONG)0x5BBEF7DD;
		m_sBox[1][221] = (LONG)0x1B588D40;
		m_sBox[2][221] = (LONG)0xCCD2017F;
		m_sBox[3][221] = (LONG)0x6BB4E3BB;
		m_sBox[0][222] = (LONG)0xDDA26A7E;
		m_sBox[1][222] = (LONG)0x3A59FF45;
		m_sBox[2][222] = (LONG)0x3E350A44;
		m_sBox[3][222] = (LONG)0xBCB4CDD5;
		m_sBox[0][223] = (LONG)0x72EACEA8;
		m_sBox[1][223] = (LONG)0xFA6484BB;
		m_sBox[2][223] = (LONG)0x8D6612AE;
		m_sBox[3][223] = (LONG)0xBF3C6F47;
		m_sBox[0][224] = (LONG)0xD29BE463;
		m_sBox[1][224] = (LONG)0x542F5D9E;
		m_sBox[2][224] = (LONG)0xAEC2771B;
		m_sBox[3][224] = (LONG)0xF64E6370;
		m_sBox[0][225] = (LONG)0x740E0D8D;
		m_sBox[1][225] = (LONG)0xE75B1357;
		m_sBox[2][225] = (LONG)0xF8721671;
		m_sBox[3][225] = (LONG)0xAF537D5D;
		m_sBox[0][226] = (LONG)0x4040CB08;
		m_sBox[1][226] = (LONG)0x4EB4E2CC;
		m_sBox[2][226] = (LONG)0x34D2466A;
		m_sBox[3][226] = (LONG)0x115AF84;
		m_sBox[0][227] = (LONG)0xE1B00428;
		m_sBox[1][227] = (LONG)0x95983A1D;
		m_sBox[2][227] = (LONG)0x6B89FB4;
		m_sBox[3][227] = (LONG)0xCE6EA048;
		m_sBox[0][228] = (LONG)0x6F3F3B82;
		m_sBox[1][228] = (LONG)0x3520AB82;
		m_sBox[2][228] = (LONG)0x11A1D4B;
		m_sBox[3][228] = (LONG)0x277227F8;
		m_sBox[0][229] = (LONG)0x611560B1;
		m_sBox[1][229] = (LONG)0xE7933FDC;
		m_sBox[2][229] = (LONG)0xBB3A792B;
		m_sBox[3][229] = (LONG)0x344525BD;
		m_sBox[0][230] = (LONG)0xA08839E1;
		m_sBox[1][230] = (LONG)0x51CE794B;
		m_sBox[2][230] = (LONG)0x2F32C9B7;
		m_sBox[3][230] = (LONG)0xA01FBAC9;
		m_sBox[0][231] = (LONG)0xE01CC87E;
		m_sBox[1][231] = (LONG)0xBCC7D1F6;
		m_sBox[2][231] = (LONG)0xCF0111C3;
		m_sBox[3][231] = (LONG)0xA1E8AAC7;
		m_sBox[0][232] = (LONG)0x1A908749;
		m_sBox[1][232] = (LONG)0xD44FBD9A;
		m_sBox[2][232] = (LONG)0xD0DADECB;
		m_sBox[3][232] = (LONG)0xD50ADA38;
		m_sBox[0][233] = (LONG)0x339C32A;
		m_sBox[1][233] = (LONG)0xC6913667;
		m_sBox[2][233] = (LONG)0x8DF9317C;
		m_sBox[3][233] = (LONG)0xE0B12B4F;
		m_sBox[0][234] = (LONG)0xF79E59B7;
		m_sBox[1][234] = (LONG)0x43F5BB3A;
		m_sBox[2][234] = (LONG)0xF2D519FF;
		m_sBox[3][234] = (LONG)0x27D9459C;
		m_sBox[0][235] = (LONG)0xBF97222C;
		m_sBox[1][235] = (LONG)0x15E6FC2A;
		m_sBox[2][235] = (LONG)0xF91FC71;
		m_sBox[3][235] = (LONG)0x9B941525;
		m_sBox[0][236] = (LONG)0xFAE59361;
		m_sBox[1][236] = (LONG)0xCEB69CEB;
		m_sBox[2][236] = (LONG)0xC2A86459;
		m_sBox[3][236] = (LONG)0x12BAA8D1;
		m_sBox[0][237] = (LONG)0xB6C1075E;
		m_sBox[1][237] = (LONG)0xE3056A0C;
		m_sBox[2][237] = (LONG)0x10D25065;
		m_sBox[3][237] = (LONG)0xCB03A442;
		m_sBox[0][238] = (LONG)0xE0EC6E0E;
		m_sBox[1][238] = (LONG)0x1698DB3B;
		m_sBox[2][238] = (LONG)0x4C98A0BE;
		m_sBox[3][238] = (LONG)0x3278E964;
		m_sBox[0][239] = (LONG)0x9F1F9532;
		m_sBox[1][239] = (LONG)0xE0D392DF;
		m_sBox[2][239] = (LONG)0xD3A0342B;
		m_sBox[3][239] = (LONG)0x8971F21E;
		m_sBox[0][240] = (LONG)0x1B0A7441;
		m_sBox[1][240] = (LONG)0x4BA3348C;
		m_sBox[2][240] = (LONG)0xC5BE7120;
		m_sBox[3][240] = (LONG)0xC37632D8;
		m_sBox[0][241] = (LONG)0xDF359F8D;
		m_sBox[1][241] = (LONG)0x9B992F2E;
		m_sBox[2][241] = (LONG)0xE60B6F47;
		m_sBox[3][241] = (LONG)0xFE3F11D;
		m_sBox[0][242] = (LONG)0xE54CDA54;
		m_sBox[1][242] = (LONG)0x1EDAD891;
		m_sBox[2][242] = (LONG)0xCE6279CF;
		m_sBox[3][242] = (LONG)0xCD3E7E6F;
		m_sBox[0][243] = (LONG)0x1618B166;
		m_sBox[1][243] = (LONG)0xFD2C1D05;
		m_sBox[2][243] = (LONG)0x848FD2C5;
		m_sBox[3][243] = (LONG)0xF6FB2299;
		m_sBox[0][244] = (LONG)0xF523F357;
		m_sBox[1][244] = (LONG)0xA6327623;
		m_sBox[2][244] = (LONG)0x93A83531;
		m_sBox[3][244] = (LONG)0x56CCCD02;
		m_sBox[0][245] = (LONG)0xACF08162;
		m_sBox[1][245] = (LONG)0x5A75EBB5;
		m_sBox[2][245] = (LONG)0x6E163697;
		m_sBox[3][245] = (LONG)0x88D273CC;
		m_sBox[0][246] = (LONG)0xDE966292;
		m_sBox[1][246] = (LONG)0x81B949D0;
		m_sBox[2][246] = (LONG)0x4C50901B;
		m_sBox[3][246] = (LONG)0x71C65614;
		m_sBox[0][247] = (LONG)0xE6C6C7BD;
		m_sBox[1][247] = (LONG)0x327A140A;
		m_sBox[2][247] = (LONG)0x45E1D006;
		m_sBox[3][247] = (LONG)0xC3F27B9A;
		m_sBox[0][248] = (LONG)0xC9AA53FD;
		m_sBox[1][248] = (LONG)0x62A80F00;
		m_sBox[2][248] = (LONG)0xBB25BFE2;
		m_sBox[3][248] = (LONG)0x35BDD2F6;
		m_sBox[0][249] = (LONG)0x71126905;
		m_sBox[1][249] = (LONG)0xB2040222;
		m_sBox[2][249] = (LONG)0xB6CBCF7C;
		m_sBox[3][249] = (LONG)0xCD769C2B;
		m_sBox[0][250] = (LONG)0x53113EC0;
		m_sBox[1][250] = (LONG)0x1640E3D3;
		m_sBox[2][250] = (LONG)0x38ABBD60;
		m_sBox[3][250] = (LONG)0x2547ADF0;
		m_sBox[0][251] = (LONG)0xBA38209C;
		m_sBox[1][251] = (LONG)0xF746CE76;
		m_sBox[2][251] = (LONG)0x77AFA1C5;
		m_sBox[3][251] = (LONG)0x20756060;
		m_sBox[0][252] = (LONG)0x85CBFE4E;
		m_sBox[1][252] = (LONG)0x8AE88DD8;
		m_sBox[2][252] = (LONG)0x7AAAF9B0;
		m_sBox[3][252] = (LONG)0x4CF9AA7E;
		m_sBox[0][253] = (LONG)0x1948C25C;
		m_sBox[1][253] = (LONG)0x2FB8A8C;
		m_sBox[2][253] = (LONG)0x1C36AE4;
		m_sBox[3][253] = (LONG)0xD6EBE1F9;
		m_sBox[0][254] = (LONG)0x90D4F869;
		m_sBox[1][254] = (LONG)0xA65CDEA0;
		m_sBox[2][254] = (LONG)0x3F09252D;
		m_sBox[3][254] = (LONG)0xC208E69F;
		m_sBox[0][255] = (LONG)0xB74E6132;
		m_sBox[1][255] = (LONG)0xCE77E25B;
		m_sBox[2][255] = (LONG)0x578FDFE3;
		m_sBox[3][255] = (LONG)0x3AC372E6;
		return BF_setKey(BF_KEY);
	}
	
	LONG f(LONG x)
	{
		UWORD a1;
		UWORD b1;
		UWORD c1;
		UWORD d1;
		ULONG  y1;
		d1 =(UWORD)(x & (LONG)0x00FF);
		x = (LONG)(((ULONG)x) >> (UBYTE)8);
		c1 =(UWORD)( x & (LONG)0x00FF);
		x = (LONG)(((ULONG)x) >> 8);
		b1 =(UWORD)(x & (LONG)0x00FF);
		x = (LONG)(((ULONG)x) >> 8);
		a1 = (UWORD)(x & (LONG)0x00FF);
		y1 = (ULONG)m_sBox[0][a1] + (ULONG)m_sBox[1][b1];
		y1 = y1 ^ (ULONG)m_sBox[2][c1];
		y1 = y1 + (ULONG)m_sBox[3][d1];
		return (LONG)y1;
	}                 





	void DecryptBlock(LONG *Xl,LONG *Xr)
	{
	    LONG i1,j1,K1;
    	K1 = *Xr;
    	*Xr = *Xl ^ m_pBox[ROUNDS + 1];
    	*Xl = K1 ^ m_pBox[ROUNDS];
    	j1 = ROUNDS - 2;
    	for(i1 = (LONG)0;i1<=(LONG)(ROUNDS / 2 - 1);i1++)
    	{
        	*Xl = *Xl ^ f(*Xr);
	        *Xr = *Xr ^ m_pBox[j1 + (LONG)1];
        	*Xr = *Xr ^ f(*Xl);
        	*Xl = *Xl ^ (LONG)m_pBox[j1];
        	j1 = j1 - (LONG)2;
    	}
	}
	
	void EncryptBlock(LONG *Xl,LONG *Xr)
	{
	    LONG i1,j1,K1;
	    j1 = 0;
    	for(i1 = (LONG)0;i1<=(LONG)(ROUNDS / 2 - 1);i1++) 
    	{
	        *Xl = *Xl ^ m_pBox[j1];
	        *Xr = *Xr ^ f(*Xl);
	        *Xr = *Xr ^ m_pBox[j1 + (LONG)1];
	        *Xl = *Xl ^ f(*Xr) ;
	        j1 = j1 + (LONG)2;
	    }
		K1 = *Xr;
	    *Xr = *Xl ^ m_pBox[ROUNDS];
	    *Xl = K1 ^ m_pBox[ROUNDS + 1];
	}
	
	INT BF_setKey(const UBYTE* key)
	{
		LONG i=0,j=0,K=0,dataX=0,datal=0,datar=0,len=BF_KEY_LEN;
		j = 0;                          
		for (i = (LONG)0;i<= (LONG)(ROUNDS + 1);i++)
		{
			dataX = (LONG)0;
			for (K = (LONG)0;K<=(LONG)3;K++)
			{
				dataX=(LONG)(((ULONG)dataX) << 8) | dataX;
				dataX = (dataX | (LONG)((key[j] >> 1) & (UBYTE)0xFF));
				j = j + (LONG)1;
				if (j >= len) 
					j = (LONG)0;
				
			}
			m_pBox[i] = m_pBox[i] ^ dataX;
		}
		
	
		datal = 0;
		datar = 0;
		for (i = (LONG)0;i<=(LONG)(ROUNDS);i+=(LONG)2)
		{
			EncryptBlock(&datal,&datar);
			m_pBox[i] = datal;
			m_pBox[i + (LONG)1] = datar;
		}
		for (i = (LONG)0;i<=(LONG)3;i++)
		{
			for (j = (LONG)0;j<=(LONG)254;j+=(LONG)2)
			{
				EncryptBlock(&datal,&datar);
				m_sBox[i][j] = datal;
				m_sBox[i][j + (LONG)1] = datar;
			}
		}
		isUsed=(INT)TRUE;
		return (INT)0;
	}
	
	void GetWord(LONG *LongValue,const CHAR* CryptBuffer,INT Offset)
	{
	    CHAR bb[4];
	    bb[3] = CryptBuffer[Offset];
	    bb[2] = CryptBuffer[Offset + 1];
	    bb[1] = CryptBuffer[Offset + 2];
	    bb[0] = CryptBuffer[Offset + 3];
	    *LongValue=*((LONG *)&bb[0]);
	} 
	
	void PutWord(const LONG* LongValue,CHAR* CryptBuffer,INT Offset)
	{
	    CHAR bb[4];                 
	    *((LONG *)&bb[0])=*LongValue;
	    CryptBuffer[Offset] = bb[3];
	    CryptBuffer[Offset + 1] = bb[2];
	    CryptBuffer[Offset + 2] = bb[1];
	    CryptBuffer[Offset + 3] = bb[0];                         
	}
	
	INT BF_encryptByte(CHAR* ByteArray,INT *length)
	{
		INT Offset=0, OrigLen=0,  CipherLen=0;
		LONG LeftWord,RightWord, CipherLeft=0, CipherRight=0;
		if (!isUsed) 
			return 1;
		OrigLen = *length;
		CipherLen = OrigLen + 4;
		if (CipherLen % 8 != 0) CipherLen = CipherLen + 8 - (CipherLen % 8);

		for(CipherLeft=(LONG)(OrigLen-1);CipherLeft>=(LONG)0;CipherLeft--)
			ByteArray[CipherLeft+(LONG)4]=ByteArray[CipherLeft];
		/*reset CipherLeft to 0*/	
		CipherLeft=0;	
		*((LONG *)&ByteArray[0])=CipherRight;

		*((LONG *)&ByteArray[0])=*length;

		for(Offset=0;Offset<(CipherLen);Offset+=8)
		{
	        GetWord(&LeftWord, ByteArray, Offset);
	        GetWord(&RightWord,ByteArray, Offset + 4);
	        LeftWord = LeftWord ^ CipherLeft;
	        RightWord = RightWord ^ CipherRight;
	        EncryptBlock(&LeftWord,&RightWord);
	        PutWord(&LeftWord, ByteArray, Offset);
	        PutWord(&RightWord, ByteArray, Offset + 4);
	        CipherLeft = LeftWord;
	        CipherRight = RightWord;
		}  
		*length=(INT)CipherLen;
		return 0;
	}
	
	INT BF_decryptByte(CHAR* ByteArray,INT* length) 
	{
		INT Offset=0, OrigLen=0,  CipherLen=0;
		LONG LeftWord,RightWord, CipherLeft=0, CipherRight=0;
		if (!isUsed) return 1;
		
		CipherLen = *length;
		for (Offset = 0;Offset<=(CipherLen - 1);Offset+=8)
		{
	        GetWord(&LeftWord, ByteArray, Offset);
	        GetWord(&RightWord, ByteArray, Offset + 4);
	        DecryptBlock(&LeftWord,&RightWord);
	        LeftWord = LeftWord ^ CipherLeft;
	        RightWord = RightWord ^ CipherRight;
	        GetWord(&CipherLeft, ByteArray, Offset);
	        GetWord(&CipherRight, ByteArray, Offset + 4);
	        PutWord(&LeftWord, ByteArray, Offset);
	        PutWord(&RightWord, ByteArray, Offset + 4);
		}

		OrigLen=*((INT *)&ByteArray[0]);
		
		if ((CipherLen - OrigLen > 11) || (CipherLen - OrigLen < 4))
		{              
//#if defined(TESTING)
//			(void)printf(" invalid blowfish descriptor !!!");
//#else
//			(void)nac_printf(" invalid blowfish descriptor !!!");
//#endif
			return 1;
		}   
		
		for(CipherLeft=(LONG)0;CipherLeft<(LONG)OrigLen;CipherLeft++)
			ByteArray[CipherLeft]=ByteArray[CipherLeft+(LONG)4];
		
		*length=OrigLen;
		ByteArray[OrigLen]='\0';
		
		return 0;
	}      
	         
#if defined(TESTING)
/*char bf_Key[]="PAVEL WINSOCK key for BlowFish encrpyption with a lot of character for better security level - should be impossible to crack!";*/
/*#define STRING "i5,3,0,0,7"*/
#define STRING "123456789" 
INT main()
{  
	char text[248];
	INT len=1,i;
	isUsed=TRUE;
	memset(text,0,252);
	BF_set();
	strcpy(text,STRING);
	printf("\ntext copied:%s\n",text);
	len=strlen(text);
	BF_encryptByte(text,&len);
	printf("\nlen resulted:%d\n",len);
	for(i=0;i<len;i++)
	{
		printf("%02x ",(byte)text[i]);
	}
	printf("\n");
	printf("\n");
	BF_decryptByte(text,&len);
	printf("\nlen resulted:%d\n",len);
	for(i=0;i<len;i++)
	{
		printf("%02x ",(byte)text[i]);
	}
	printf("\n");
	return 0;
}        
#endif
