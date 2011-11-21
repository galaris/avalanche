#include "c_interface.h"

int main(int argc, char *argv[]) {
  VC vc = vc_createValidityChecker();
  vc_setFlags('n');
  vc_setFlags('d');
  vc_setFlags('p'); 
 
  Expr nresp1 = vc_varExpr(vc, "nresp1", vc_bv32Type(vc));
  Expr packet_get_int0 = vc_varExpr(vc, "packet_get_int0", vc_bv32Type(vc));
  Expr sz = vc_varExpr(vc, "sz", vc_bv32Type(vc));
  Expr exprs[] = {
    // nresp1 == packet_get_int0
    vc_eqExpr(vc, nresp1, packet_get_int0),
    
    // nresp1 > 0
    vc_bvGtExpr(vc, nresp1, vc_bv32ConstExprFromInt(vc, 0)),
    
    // sz == nresp1 * 4
    vc_eqExpr(vc, sz, vc_bv32MultExpr(vc, nresp1, vc_bv32ConstExprFromInt(vc, 4))),
    
    // sz > nresp1 || sz < 0
    vc_orExpr(vc, vc_sbvGeExpr(vc, sz, nresp1), vc_sbvLtExpr(vc, sz, vc_bv32ConstExprFromInt(vc, 0))),
  };
  
  Expr res = vc_andExprN(vc, exprs, sizeof(exprs)/sizeof(exprs[0]));
  //vc_printExpr(vc, res);
  vc_query(vc,res);
  vc_Destroy(vc);
  return 0;
}

