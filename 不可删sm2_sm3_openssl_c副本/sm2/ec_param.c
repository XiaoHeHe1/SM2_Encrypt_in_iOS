#include "ec_param.h"
#include "xy_ecpoint.h"

ec_param * ec_param_new()
{
	ec_param *ecp;
	ecp = (ec_param *)OPENSSL_malloc(sizeof(ec_param));
	ecp->ctx = BN_CTX_new();
	ecp->p = BN_new();
	ecp->a = BN_new();
	ecp->b = BN_new();
	ecp->n = BN_new();
	return ecp;
}
void ec_param_free(ec_param *ecp)
{
	if (ecp)
	{
		BN_free(ecp->p);
		ecp->p = NULL;
		BN_free(ecp->a);
		ecp->a = NULL;
		BN_free(ecp->b);
		ecp->b = NULL;
		BN_free(ecp->n);
		ecp->n = NULL;
		if (ecp->G)
		{
			xy_ecpoint_free(ecp->G);
			ecp->G = NULL;
		}
		if (ecp->group)
		{
			EC_GROUP_free(ecp->group);
			ecp->group = NULL;
		}
		BN_CTX_free(ecp->ctx);
		ecp->ctx = NULL;
		OPENSSL_free(ecp);
	}
}
int ec_param_init(ec_param *ecp, char **string_value, int type, int point_bit_length)
{
	ecp->type = type;
	if (TYPE_GFp == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GFp;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GFp;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GFp;
	}
	else if (TYPE_GF2m == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GF2m;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GF2m;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GF2m;
	}

	BN_hex2bn(&ecp->p, string_value[0]);
	BN_hex2bn(&ecp->a, string_value[1]);
	BN_hex2bn(&ecp->b, string_value[2]);
	BN_hex2bn(&ecp->n, string_value[5]);
	ecp->group = ecp->EC_GROUP_new_curve(ecp->p, ecp->a
		, ecp->b, ecp->ctx);
	ecp->G = xy_ecpoint_new(ecp);
	BN_hex2bn(&ecp->G->x, string_value[3]);
	BN_hex2bn(&ecp->G->y, string_value[4]);
	if (!ecp->EC_POINT_set_affine_coordinates(ecp->group
		, ecp->G->ec_point, ecp->G->x
		, ecp->G->y, ecp->ctx))
		ABORT

	ecp->point_bit_length = point_bit_length;
	ecp->point_byte_length = (point_bit_length + 7) / 8;

	return SUCCESS;
}
