package hera

import (
	"HHELand"
	"HHELand/rtf_integration"
)

type TestCase int

const (
	ENC TestCase = iota
	DEC
)

const (
	HR80F = iota
	HR80S
	HR80AF
	HR80AS
)

const (
	HR128F = iota
	HR128S
	HR128AF
	HR128AS
)

type TestContext struct {
	TC           TestCase
	FVParamIndex int
	Radix        int
	Params       Parameter
	Key          HHELand.Key
	Plaintext    HHELand.Plaintext
	Ciphertext   HHELand.Ciphertext
}

// TestVector Test Vectors
var TestVector = []TestContext{
	//	HERA 80 bits security
	{
		TC:           ENC,
		FVParamIndex: HR80F,
		Radix:        2,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR80F].PlainModulus,
			Rounds:    4,
		},
		Key: HHELand.Key{
			0x6d3c611, 0x9d41950, 0x2e14372, 0x9baa181,
			0x422bf14, 0xebeebc5, 0xaccbfb5, 0x7445893,
			0x62b4f8, 0x5ff653c, 0x2558d94, 0xb9d1aea,
			0x4ffbf51, 0xf1dc323, 0xabbc1ac, 0x99cce83},
		Plaintext: HHELand.Plaintext{
			0x4f7ec94, 0x4d8e45a, 0x365cd14, 0x7a459a4,
			0xef484d9, 0xa4ae3f6, 0xdebfb39, 0xce3516,
			0x2c015c0, 0x92de0c6, 0xea71f98, 0xecc0e0a,
			0xdb3c8ab, 0xae2b41b, 0xe31504b, 0xaf909a4,
			0x53ee2bd, 0x5641631, 0xb1dd39f, 0x1c86148,
			0x104aed7, 0xc654911, 0x5d7ceba, 0x4d5468e,
			0x9634756, 0x980c101, 0x503b1e1, 0xff4cd97,
			0xe0fe756, 0x38c3c8d, 0xdae5c00, 0xd9052f7,
			0x1830088, 0x6942d6, 0x6c1b22d, 0x84aac51,
			0x1d777d1, 0xfa42388, 0xc1f6c31, 0xcfcc576,
			0xd5e2557, 0xdd34947, 0xd1e0117, 0x7775865,
			0x7398fe0, 0xe6576ba, 0x112bbff, 0x20c1304,
			0xcf8b5a, 0x1f11284, 0x8bb24, 0xd839939,
			0x6bfcafa, 0x698ffb4, 0xd4c7fa9, 0xce3c981,
			0xe727edb, 0xf4f73d6, 0xef59cdc, 0x31d60f6,
			0xe851bc1, 0x145864f, 0xbffd70d, 0x7d57182,
			0xe76fd17, 0xcc178c8, 0x603174c, 0xc27e6c5,
			0xb5f7261, 0x86f7823, 0x8d6690d, 0xa56e39,
			0xd2adc40, 0xb75f16a, 0xf4ee9d, 0xa086898,
			0x87c7f65, 0x51fb725, 0x733708e, 0x9acca17,
			0x9a26ccd, 0x12a3ff4, 0x12a425a, 0x66264c7,
			0x7f9fd60, 0xc422aac, 0xd12e780, 0x6847680,
			0x4491668, 0x9608219, 0x6adf55b, 0x34560bc,
			0xc4b9232, 0xb55604f, 0x2e85f9d, 0xc571dc,
			0xecf88a2, 0xf084116, 0x4572e27, 0x31bba23,
			0xde1b9f8, 0x60022d3, 0x662f949, 0x9f261c,
			0x350c3fc, 0x4c7105f, 0x85443d9, 0xd4ef7b1,
			0x5f04260, 0x9d3efe6, 0xa112d7, 0x76912c9,
			0x453fc8, 0xdc1b5d1, 0x753e870, 0xf578924,
			0xbed846a, 0xcd470c0, 0xf4c5c27, 0xfe43a4a,
			0x9c1f121, 0x689e723, 0x2851f6a, 0x1b0d88e,
			0x1b38b06, 0xa93f98b, 0x88f60b, 0x641b4a9},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR80S,
		Radix:        0,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR80S].PlainModulus,
			Rounds:    4,
		},
		Key: HHELand.Key{0x84beeb4, 0x2df4e30, 0x9669076, 0x3115ba4,
			0x874f0cb, 0x4331592, 0x34c5300, 0x5f1dd49,
			0x7574d80, 0xe38c008, 0xfcd0f7, 0xf567c22,
			0x566eaaa, 0x8a46537, 0x66c422a, 0xd9453ce},
		Plaintext: HHELand.Plaintext{0x34e4282, 0xa4a4426, 0x755bb7c, 0xeaf06e1,
			0x3fb917a, 0xf8ff31a, 0xcff2d0b, 0xbe18bbf,
			0xf12e325, 0x39b7de0, 0xb091cd, 0x9ec7a09,
			0xb26857e, 0x867f044, 0xea5ce3, 0x3ff6dff,
			0xe5e58f7, 0x60895ac, 0xbf45d62, 0x7540b6b,
			0x899fb69, 0xd3166d0, 0xf4cfe5a, 0xfbd4ee4,
			0x5d09c76, 0xb02ec1e, 0x4b2a65b, 0x40bed9c,
			0xe31fafd, 0x6de4039, 0x5558bfc, 0x4b2c86c,
			0x9c2242, 0xb798ef9, 0x396ac5, 0xf037876,
			0xbb12b30, 0x1ffaba3, 0xbb8b3e1, 0x798abdf,
			0x205a117, 0x480834f, 0xf752cce, 0x8413352,
			0xf21cd7e, 0x53f3ac0, 0x8e83f4c, 0x258faad,
			0xcedeaac, 0x424cb30, 0xdb7f698, 0xd370754,
			0xe1485c5, 0x760933d, 0x7c5ab6e, 0x60a3b94,
			0x385781b, 0x727d007, 0xebdebbd, 0x7250066,
			0xa9f6653, 0xfd5ee04, 0x4e8d05f, 0xc374f56,
			0x2ca33be, 0x5733139, 0x5934a89, 0x20b422,
			0xf96c62, 0x1ac347f, 0x3731a1e, 0xabe7496,
			0x18ddc8b, 0xb9ec77a, 0xa249c8c, 0x3100b8f,
			0x8ade1af, 0x19e9f95, 0x6485886, 0xf13fee4,
			0xe356279, 0x52892e4, 0x183b5fe, 0x43546e3,
			0xa8c2770, 0x4ee528c, 0x3cac2f9, 0x8024019,
			0x8f1f1ca, 0x8dbc4a6, 0xfcbb417, 0x704a0a1,
			0x5d1c0fb, 0x68aa32d, 0xbbe4e56, 0x3de8a7f,
			0x4a933d2, 0xf208033, 0xd722e4d, 0x4c27c5a,
			0xe7ffbe9, 0x46a0032, 0xd4877d6, 0xde4f585,
			0x12c9809, 0x5b95102, 0x4a27907, 0x66b8f0d,
			0x5c44d54, 0x5f5e32e, 0x8573492, 0x4afceef,
			0xf35b665, 0x1920def, 0x6c8a8ed, 0x33c8847,
			0x265635, 0x8c01e7b, 0xe9f1493, 0x936698b,
			0xfba3a04, 0x58aacf1, 0x16fcb56, 0x346366a,
			0x12721e8, 0x750adaf, 0x8a1c799, 0xac4f570},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR80AF,
		Radix:        2,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR80AF].PlainModulus,
			Rounds:    4,
		},
		Key: HHELand.Key{0x6e8a, 0x64dbc6, 0xbb2c45, 0xbe69c8,
			0x16169f7, 0xfa7b7c, 0x13263a9, 0x1a13402,
			0x18e21ff, 0xc46e7f, 0x1676264, 0x2a8045,
			0x1f3a4cd, 0x1c8fc4b, 0x25863c, 0x1d9ee07},
		Plaintext: HHELand.Plaintext{0x10a2d21, 0x2da472, 0x1e64975, 0x5c636e,
			0x154c6d1, 0x9c7d2c, 0x13db647, 0xa2e1da,
			0x8a0292, 0x1c3c802, 0x1d29221, 0xf85583,
			0x56a45e, 0x6b173f, 0x12bb4b0, 0x4bd67e,
			0x30f2c3, 0x987999, 0x6b8e45, 0x446a23,
			0x4b94d3, 0xb88b65, 0x19d7ea1, 0x301f04,
			0x37779, 0x78e946, 0x55abf8, 0x16190e4,
			0x57dd9c, 0x4ad3b5, 0x1eec895, 0x19be5f7,
			0x6f926, 0xeb9085, 0x68fccb, 0x190338a,
			0x75382e, 0x15c7628, 0xf2d788, 0x1310e1f,
			0x13baadf, 0x95b943, 0xb89321, 0xec1261,
			0x12ac5fa, 0x15615b9, 0x1a9034e, 0x1299ae6,
			0x13013bb, 0x7063fb, 0x2b6a14, 0x1f49cf,
			0x118f1f9, 0x24b955, 0x62924, 0x1358d7e,
			0x49f6f, 0x17fdc2d, 0x1e791cf, 0x1ac9616,
			0x1145e93, 0x13bf9e8, 0x1e0060d, 0x180a295,
			0x6cdc70, 0x6f3cf8, 0x1824bd0, 0xca7cc6,
			0x1a70c8f, 0x1d5a9f9, 0x1300d1c, 0x1041f9f,
			0xbd460d, 0x8a3596, 0x5cba48, 0x7c2c15,
			0x179640d, 0x7b3d12, 0xb92f9a, 0x150da50,
			0xaf4ca6, 0x1c7809b, 0x1410375, 0x11b196b,
			0xfd2a9e, 0x14cbb9c, 0xf322bd, 0xc5d95f,
			0x1cb7ce9, 0xff0e98, 0x77f521, 0xaca7dc,
			0x4f6955, 0x14589fb, 0x110c4b2, 0x3d1a89,
			0x15f002e, 0xd49ad0, 0x10fc471, 0x9283a1,
			0x1d92240, 0xf693ba, 0x1409d5, 0xe363ee,
			0x193d56a, 0x9a7972, 0x128a133, 0x6d0c06,
			0xc31447, 0x1a513e8, 0xd7a19f, 0x1dbd57a,
			0x15ae011, 0x11eea4d, 0x68b78d, 0x1363961,
			0x16bc7d9, 0x1059003, 0x9f66fc, 0x73737e,
			0xe592a7, 0xe47342, 0x21ea54, 0xe4fb2,
			0x9568a1, 0x1efe21, 0x1dd74df, 0x132055a},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR80AS,
		Radix:        0,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR80AS].PlainModulus,
			Rounds:    4,
		},
		Key: HHELand.Key{0x85b819, 0x11344b, 0x109583f, 0x6bb6a0,
			0xc31619, 0xd5af0b, 0x1f25bd9, 0x13baa72,
			0xea531c, 0x1097bfe, 0x1524654, 0x1525b79,
			0x154cbeb, 0x1ee23a, 0xe93d3, 0x1426558},
		Plaintext: HHELand.Plaintext{0x147ba5, 0x1f1c01c, 0xb26f2c, 0x109a3ad,
			0x33d1f1, 0x2a007d, 0x4bf742, 0x1f0e2aa,
			0x14640d0, 0xbbba57, 0xfaba77, 0xd6ec41,
			0xb5495, 0x1a0d058, 0x18e0ae7, 0x1466eaf,
			0x18e7ba, 0xd6709, 0x6ea685, 0x1b4f529,
			0x3c55ca, 0xe9ce0d, 0x1ee228b, 0x6adde5,
			0xb0e589, 0x4b454b, 0x87556f, 0x87aa22,
			0xc58d43, 0x116964b, 0x1ce351e, 0x18e79a5,
			0xa8ab9a, 0x3d252, 0x1797b30, 0xafade2,
			0x263fd6, 0x81f619, 0x1034d18, 0x16c1905,
			0x8d4431, 0x1df5114, 0x1b6425d, 0x1936496,
			0x1d0bc7d, 0x99a05e, 0xbb4fee, 0x1da5951,
			0x42f07e, 0x191eb8b, 0xe13623, 0x194a580,
			0x926cbc, 0x7b2973, 0xf1bee1, 0x70a0ec,
			0x17b0880, 0x1258aa6, 0x1c1f39d, 0xac48f9,
			0x1142f2e, 0xb50be0, 0xfa655a, 0x2f2198,
			0x14396dd, 0xe359c5, 0xd16d49, 0x1283f21,
			0xbe8fa6, 0x62e6b, 0x9328cc, 0x1a16e05,
			0x1d84c06, 0x50eccb, 0x76244a, 0x14280c9,
			0x1bd710a, 0x1f08ae8, 0x795c00, 0x1569789,
			0x27dec4, 0x1420e9, 0x144fb34, 0x18b88a5,
			0x6a3219, 0x1c5a128, 0x106472, 0xef8596,
			0x1e93246, 0xa40487, 0xe61334, 0x741c33,
			0xd22800, 0xe7af93, 0x18e4dbd, 0x1fbf638,
			0x1302e9d, 0xc2995, 0xa6c013, 0x17a5e0a,
			0x7dad1c, 0x11213ef, 0xe014f6, 0x1042ac1,
			0x17b33ce, 0x1595baa, 0x34bd58, 0x164659a,
			0x1cced93, 0x8ecdb6, 0x156e203, 0x1b07f32,
			0xd42435, 0x441f66, 0x8206c6, 0x9f3322,
			0x4b51be, 0x969d57, 0xbbdbbb, 0xdb4be2,
			0x7521bc, 0x1de63c0, 0xac9f3f, 0x14e3c4d,
			0x7b849b, 0x1cc7922, 0xb4275, 0x158ebf9},
		Ciphertext: HHELand.Ciphertext{},
	},
	//	HERA 128 bits security
	{
		TC:           ENC,
		FVParamIndex: HR128F,
		Radix:        2,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR128F].PlainModulus,
			Rounds:    5,
		},
		Key: HHELand.Key{0x605ae5b, 0x62be1ef, 0x9dc75ea, 0x81e09a7,
			0xf15fcd7, 0xa6c05b8, 0xef3d901, 0x7530002,
			0x9ba3ea1, 0x7a643fc, 0x3cc3e91, 0xd567b7a,
			0x94ef7f4, 0x8bf2919, 0x68625cf, 0xd3741ac},
		Plaintext: HHELand.Plaintext{0x5363413, 0x56c4780, 0x736d68f, 0xa59c40,
			0xaf2e3e1, 0xf283c83, 0x1ac37bc, 0x9543afd,
			0x875b9b7, 0xa7443cc, 0x9b97c65, 0x500406f,
			0x36ad9a1, 0xe00f6a8, 0xedac574, 0x4ed0613,
			0x3506446, 0xcb0b4e0, 0x403437f, 0x7a69117,
			0x85384d8, 0xec2c7e4, 0x1dfa8bf, 0x4aa986d,
			0x305fa73, 0xb3d287a, 0x4e059e0, 0x309122d,
			0x8411c13, 0xe296f55, 0x530208e, 0x641215a,
			0xc45a3f8, 0x9b5fec9, 0xfbaa740, 0xce7051,
			0xad82bb2, 0xdcdfcdd, 0x929b11c, 0xf2051e3,
			0x655db2f, 0xada0a99, 0x7322e78, 0xbe71882,
			0xed55f0a, 0x8a5ba81, 0xd03dfed, 0x519f83b,
			0x51c8cae, 0xb0c1810, 0x83b9b72, 0x691ba93,
			0x5b58f76, 0xa04c1bd, 0x86fc49a, 0xbb0a661,
			0x7c4acd0, 0xc93538b, 0x3120f43, 0x28e7bf4,
			0x32691b8, 0x1e24287, 0xfa0f46f, 0x1d25d38,
			0x708fc17, 0xed2af26, 0xdb1bcb4, 0xf05c530,
			0xc9cf0f, 0xfa49db9, 0x24e0b92, 0xe42d692,
			0xe7067e7, 0x9939235, 0xe7d472c, 0xbc6cf68,
			0xb68f61a, 0xb95cfbc, 0xa143b6d, 0xbfc8670,
			0x5fc3928, 0x4a5686, 0x5069f00, 0x292f316,
			0x294a11f, 0x505a9a8, 0x3d6ac3a, 0xbde39e0,
			0x8064dd0, 0x50a7ab3, 0x744b6f6, 0x30b493b,
			0x5215a49, 0x14242c2, 0xe8b089d, 0xbd10d02,
			0x3c32035, 0x86cd8f9, 0x6f7a9fe, 0x91c72e8,
			0x53aa0cc, 0xc3f1bea, 0x622506a, 0xd7cd815,
			0xa8a449d, 0xb02ce0a, 0x843a92c, 0x3ebdf37,
			0x759dddd, 0xf725376, 0x63b824a, 0xa783c6a,
			0x307551e, 0x60cdfcb, 0xc787e53, 0xdf82bd7,
			0xed78ac, 0xdf2e7dc, 0x5b8e7ce, 0x76dbbe0,
			0x259dbbd, 0xc2f1b29, 0xd1de26c, 0x968b395,
			0x6af6be6, 0xefd36ff, 0xcf9bcc4, 0xcc395d8},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR128S,
		Radix:        0,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR128S].PlainModulus,
			Rounds:    5,
		},
		Key: HHELand.Key{0xb52bd22, 0xb54da27, 0x8f873e6, 0xeb0707d,
			0x179bf8d, 0x16265cf, 0x16c0063, 0x7f5f3e5,
			0xa46fe6c, 0xc8d9217, 0xeea8b32, 0x91f2ff3,
			0x353e66e, 0x91715a, 0xd98cb57, 0xf4b9fd7},
		Plaintext: HHELand.Plaintext{0x84b3d61, 0xed29140, 0x6396c4a, 0x23d4fd4,
			0x1eae72d, 0x53af326, 0x48e7e7f, 0x401f276,
			0xacbe5f, 0x31a19a0, 0x9ef8b5e, 0x915dd61,
			0xd74ef7e, 0xbf2caf, 0xeee35e5, 0x2c3477e,
			0xeb97cff, 0x4ba8f83, 0x6a3e6fc, 0x9a1ea97,
			0x3b6e1c4, 0x61d5145, 0xf846390, 0xc9ba455,
			0xb1cbddc, 0x65d0679, 0x7ac05f4, 0x6b813fc,
			0x119fc21, 0x41cd2, 0x933e267, 0xda83719,
			0xc18ee62, 0x44167b5, 0xc90982c, 0xacc3028,
			0xda8c4bc, 0x33596b0, 0x7180986, 0xee837be,
			0x816f45, 0xa807b54, 0xa964d0b, 0x9475386,
			0x2df38a3, 0x534723f, 0x30663e5, 0x649d59e,
			0x5186082, 0x88a35b3, 0x7e5431a, 0xd862361,
			0x9f18c34, 0x735b422, 0xa3727af, 0x610fa6a,
			0xe04b2c0, 0x392dfda, 0xfdf00b9, 0xd1ae9a3,
			0xf9ccde1, 0xf736592, 0x106d938, 0x6936429,
			0xf6feae0, 0x351e968, 0xa3959d, 0xc4f4447,
			0xf2b31c7, 0x89ff955, 0x590b417, 0xecea5b2,
			0x4044ce8, 0x889976b, 0xc32d36a, 0x8c6c94,
			0x48985d2, 0xd5c04b1, 0x3e1b3c7, 0x1d504df,
			0x4b04b56, 0xae0fa8e, 0x2720cc4, 0x8ae02e6,
			0x5edbf8e, 0xb184ead, 0x8f6543a, 0x46d65b3,
			0x11685b7, 0xd6eed98, 0x4bcbc2c, 0x1d7aee2,
			0xb8598f1, 0xee492b3, 0x8e31bb5, 0xedf2d66,
			0xa220458, 0x405f0ce, 0xdb2f86c, 0x93f92be,
			0x5ad4d86, 0x652eebb, 0xb2752ae, 0x50301b2,
			0xb8c8bfb, 0x5b2d3f5, 0xbae7d32, 0xca976c3,
			0x29a9051, 0x9435103, 0xb106c7a, 0xe6ce55,
			0x66e7e7, 0xb90cc61, 0x9c4f312, 0xc2d3963,
			0x941c671, 0x49eb399, 0xddd56a8, 0x2fde8ba,
			0x3a8aff, 0x3f91345, 0x6265d41, 0x6f54eb3,
			0x20aa6a, 0x3c0f2f3, 0x1c0ff7d, 0x9596f3e},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR128AF,
		Radix:        2,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR128AF].PlainModulus,
			Rounds:    5,
		},
		Key: HHELand.Key{0x1808681, 0x13578fc, 0x1828cf, 0x1bc1199,
			0x11aab0, 0x122655c, 0xdde5b5, 0x1c576b0,
			0x10a2079, 0x10c51ac, 0x184fe01, 0x16cc1e2,
			0x588629, 0x1b36bbc, 0x7d050a, 0x56f642},
		Plaintext: HHELand.Plaintext{0x764370, 0xf7b65d, 0x1e19ecb, 0x15fd92b,
			0x1eee5e8, 0x910386, 0x9c27d, 0x9b87af,
			0x1ef67e9, 0x14a31d5, 0x8892e9, 0x106bc04,
			0x132716a, 0x11894ca, 0x1c7408b, 0xca79fc,
			0x14d05d1, 0xa50df1, 0xdfc5b, 0x1d5b1eb,
			0x15c46ae, 0x8ea78c, 0x15587a7, 0xe49ead,
			0xc19ab2, 0x8b36db, 0x1c4529, 0x1777ab6,
			0x17ba81f, 0x1aa1165, 0x570ea2, 0xa1e679,
			0x9e6bf3, 0x7c5012, 0xeb1b98, 0x10d1dd2,
			0x2bc9af, 0x71cf0f, 0xeb6cd1, 0x1f5cd76,
			0xa2d9c1, 0x9ebed4, 0x32fcb9, 0x12ccc4,
			0xb79f76, 0xab2eea, 0x1b99fa8, 0xe64d,
			0x1762b8a, 0x9a0166, 0x167f114, 0x166ddaf,
			0x681b75, 0x10b4835, 0x1a350cf, 0xabb4ec,
			0xb01c39, 0x94544, 0x897f9d, 0x1b42726,
			0xbf04f2, 0x187b18f, 0x1fcf14, 0xaba6f9,
			0x3fd651, 0xca2523, 0x1337fdc, 0x12ada9,
			0x1857116, 0x1af92f6, 0x11cbcb2, 0xf86588,
			0x19a8eff, 0x59b49f, 0x1bfc084, 0x8b8161,
			0xb1bbdb, 0x46737c, 0x1cc9134, 0x15d41ea,
			0x36d0d9, 0x1939d53, 0xbf9e40, 0xfcaece,
			0x693f4a, 0x1316971, 0x633e3c, 0x15c1c85,
			0x1208704, 0x13966c9, 0x7a59a, 0xf17f88,
			0x11ffb3, 0xe511c0, 0x17b5a8e, 0xbbde1b,
			0xb1b4fd, 0x1b26af4, 0x1f1433c, 0xb9335b,
			0x17250ef, 0x5ef70a, 0xc00c0f, 0x1696636,
			0xef0334, 0xd090d7, 0x1a282db, 0x97bd7,
			0x737e32, 0x426fed, 0x814ae8, 0xdeafc9,
			0x15f8b71, 0x3a47d6, 0xc09ade, 0x20876e,
			0x2ecbf7, 0x176b70f, 0x12dca5c, 0x183a5cf,
			0x58788c, 0x1675bd5, 0xba896, 0x308ab5,
			0x1aea379, 0x133b9e4, 0x174b5b9, 0x1dadb7c},
		Ciphertext: HHELand.Ciphertext{},
	},
	{
		TC:           ENC,
		FVParamIndex: HR128AS,
		Radix:        2,
		Params: Parameter{
			BlockSize: 16,
			Modulus:   RtF.RtFHeraParams[HR128AS].PlainModulus,
			Rounds:    5,
		},
		Key: HHELand.Key{0xf1741, 0xb46639, 0x1a3ecaa, 0xd42827,
			0xe35f0b, 0x7536ec, 0x8faabb, 0xd06bf5,
			0x1d66e2c, 0xa2814, 0x1da6be3, 0xd6cc6e,
			0xf72639, 0x186cf8c, 0x3c952d, 0x4916d1},
		Plaintext: HHELand.Plaintext{0xa7d4b3, 0x9a7af0, 0x1400704, 0x174e573,
			0xad9443, 0x11340b, 0x2533b, 0xcb5091,
			0x23adc3, 0x158cc0d, 0xc60f43, 0x15a5786,
			0x1dc63d8, 0x17fb74a, 0x174272f, 0x1316b5d,
			0x158868d, 0x191d18b, 0x769118, 0x1d64c99,
			0x605d7d, 0xdf34cf, 0x1681512, 0x1226be2,
			0xa11fdb, 0x1513fce, 0xf63d35, 0x11612e6,
			0x16720be, 0x19bee92, 0x57de9d, 0x6db3ce,
			0x18fb0c9, 0x1bb6e88, 0x9b3e58, 0x92a01a,
			0x1be54ad, 0x12c2d5a, 0xfdc8b9, 0x5075e6,
			0x1c71c70, 0x1ded579, 0x40c5b0, 0x1cebff1,
			0x471571, 0x10ec77f, 0x861780, 0x10d16e,
			0x6a9ea4, 0x4fcb28, 0x1aa2788, 0x1bec102,
			0x11997d8, 0x177ed92, 0x3d4e8a, 0x11ab798,
			0x1338248, 0x10ede34, 0x1c23ab9, 0x137d419,
			0x1f3b3f7, 0xca61e6, 0x1ec11b4, 0x163aadc,
			0x1424944, 0x16c8611, 0xac484d, 0xca5b09,
			0x68230f, 0x11cd772, 0xefc8b4, 0x1d75d6f,
			0x1380df2, 0x3794cc, 0xea16f7, 0xea1646,
			0x1f76ca2, 0xdf790c, 0x161153f, 0x4f6e31,
			0x16e66e0, 0x35e904, 0x1c48577, 0x1eb8969,
			0x6bb93a, 0x1dfbc08, 0x1e1f37c, 0x1f88c0f,
			0x1c8db52, 0xc88d79, 0x128237, 0xd89bd3,
			0xcd199f, 0x13fc7a1, 0x164ff90, 0xa96d07,
			0x986bb9, 0x4af190, 0x1b29303, 0xaaadc3,
			0x1345392, 0x5c5c1, 0x5ef33, 0x1d93cd6,
			0x595440, 0x7a614a, 0xfa6b51, 0x196ef4f,
			0xf078aa, 0x1d56228, 0x26860a, 0x1880232,
			0x17416f1, 0x16b0f82, 0x1f88014, 0x1f5eb88,
			0xd35df8, 0x1f5e9ae, 0x1b3b46a, 0x168492a,
			0xb7ea18, 0x15c406, 0x2d6da5, 0x1090f1e,
			0x1a7d4fa, 0x1e1a0fb, 0x128755, 0x15e83a6},
		Ciphertext: HHELand.Ciphertext{},
	},
}
