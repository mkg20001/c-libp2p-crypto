#include <gtest/gtest.h>

#define HEX_KEY "080012A809308204A40201000282010100A95B1185B648E6B64E69414EB456D4004B7DB2115CAD0FC6D476A144B7913569E9C3D65F94660F4E3EAA7713A33A66755EF102873D44C777A447A9A761BF0A37196AD98E14A01F965AB810AAD0A7E97C28C9B843A491692C1D148B440228E828A55729576882A0DF1EB2C7CB474301103954761B15B4F4B660847929EDCACA094E4AE6F09D724E899E45619282A12E75462731B168CF1EAA0B33C1D964D068539FA91D24AB6825FB10185C542BD54955CBAD1D98112E3F651FBFF6C4E8CD126FE1C51559ADDADEED72560E27A6DBBF8F45ECE7E7EC6211210C4AB8452E6F9D3BD1C60F444A02223F49D7D5202D842CB34941ADC4AE596F32E06D0092E534D88B02030100010282010100A434A0B0BD25C24D5189CCC0BB2AD533D3FE740151929B9175BFF06DE86EEB135E8D7BF600B55471D16107440B283CDFE0C65E65328AD5BCB394A8729ADBD8D3C3D94E47ECC7B4D8DBED4C7BD3047BE6DEC577DC5E5C7F553E7D04EB540CC5CD634337DA8082E7E86EA37A05277B58349AE1C20250F1BBB479B0F8AA26DE51355091D26FA4C8B00F1F2A00A053EB6FDA409009F41F64FD55F27059D5E66538B04B49C1744D15B270CF485D0E05049A8D11D2C4FBB9278F1620546A7119759D6E20E38A6C04370F19C9CA13135E4C52D86CE884BB99214C38D1750BA5590B64B65A118E316A527121DA8D02B1E3275BE112ADFB1A03F489AE6E0630211A8EC80102818100D8BA6AEF63916CF60BCC274A6899D0B5E062E22A69493BF91800470ECCCCA8031B19BC9630CE12BAEB438EF365AE7880B87193868CDB20C243FAEEE4D647709833A8AB6281AC76FE74F62C71DC86B0D6C28CDA2F1C32D3E4885FD635C1CCCBEBCC0EE52050FC3451319C468A85B206AFA9754BA207E59CA6560110FBC977198102818100C80B23664D26828832BF3B34F89FAB136B23D443B27D5B9ADFA501E7B23CAC26166C530F67418AD41A6A968FDA69DAE9D87A855634AC0A4EFFD30A1BF075E05A5888DA72E01B608CAF8E7F94C81C122673102E945EBFABBE47FA9F6E945F45FA121FD02CF676239B79AADB646AD65FDD5759971EF295AC500BFF965968F6C00B02818100C113AA8AA4087DAAE12DBA5F26BAC95E0E8DE970E12556217EC958848DDD515C9AFB1DB02BC09A9D1D54AD7897408CA818294EC5529D311D00550018ABF12F14D908CDCE4F39E7349FDC6411F7E5A28B60FCFCAF758EAE88ED197C0B9E20A616E64EEABF1486EAD0DEC29B7172D3FBF2E8A3CF828548807B0B299E08C21DB181028180647F13FDA4EC9FCF048F85930B044BD1A9958A61A81DCA13781F5161B0ED421EB04D233D2DC6839422E1415A6B839A72B84A7509E5D438298FE3D9C4477D3084B2CDADD0E03D60B7CCCA6DD5B4E2454C03AA317C604D325E999292DDDEB42E577F1B745DE2435F88100B81C464D7E5B930D4D552BAD3EE89183E02AE504906190281803E839C53AA4131523975EAF481B7A4029E162802CD60B74135EACA1147CE4338E3B14DBD1B3495667386BC479D56B4E18475CE1E6154D2068D65D55D913B6B6E521C4E3399DA38D4DF31FB91EC3CC47F661D8AA1DE528C8E34F70E6BF5DECDA58E5AE03E22044573ED4D03F9E2505484D95BFF81E6F82BF10C7519EBA3150E3B"

extern "C" {
  #include <crypto/util.h>
  #include <crypto/keys/keys.h>
}

TEST(Keys, LoadKey) {
  ProtobufCBinaryData key = fromHex(HEX_KEY);
  char * hex = toHex(key);
  ASSERT_FALSE(strcmp(HEX_KEY, hex));
  ASSERT_TRUE(key.data);
  Libp2pPrivKey * privKey = unmarshal_private_key(key);
  ASSERT_TRUE(privKey);
  EXPECT_TRUE((RSA *) privKey->data);
  EXPECT_TRUE(privKey->type == KEY_TYPE__RSA);

  free(hex);
  free_private_key(privKey);
  free_data(key);
}

TEST(Keys, LoadAndStore) {
  ProtobufCBinaryData key = fromHex(HEX_KEY);
  Libp2pPrivKey * privKey = unmarshal_private_key(key);
  ASSERT_TRUE(privKey);
  ProtobufCBinaryData mkey = marshal_private_key(privKey);
  ASSERT_TRUE(mkey.data);
  char * hex = toHex(mkey);
  ASSERT_FALSE(strcmp(HEX_KEY, hex));

  free_private_key(privKey);
  free_data(key);
  free_data(mkey);
  free(hex);
}

TEST(Keys, Sign) { // TODO: add
  Libp2pPrivKey * privKey = unmarshal_private_key(fromHex(HEX_KEY));

  free_private_key(privKey);
}
