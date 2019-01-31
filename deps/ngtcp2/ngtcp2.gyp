{
  'target_defaults': {
    'defines': [
      '_U_='
    ]
  },
  'targets': [
    {
      'target_name': 'ngtcp2',
      'type': 'static_library',
      'include_dirs': ['lib/includes'],
      'defines': [
        'BUILDING_NGTCP2',
        'NGTCP2_STATICLIB',
      ],
      'conditions': [
        ['OS=="win"', {
          'defines': [
            'WIN32',
            '_WINDOWS',
            'HAVE_CONFIG_H',
          ],
          'msvs_settings': {
            'VCCLCompilerTool': {
              'CompileAs': '1'
            },
          },
        }],
      ],
      'direct_dependent_settings': {
        'defines': [ 'NGTCP2_STATICLIB' ],
        'include_dirs': [ 'lib/includes' ]
      },
      'sources': [
	'lib/ngtcp2_acktr.c',
	'lib/ngtcp2_addr.c',
	'lib/ngtcp2_buf.c',
	'lib/ngtcp2_cc.c',
	'lib/ngtcp2_cid.c',
	'lib/ngtcp2_conn.c',
	'lib/ngtcp2_conv.c',
	'lib/ngtcp2_crypto.c',
	'lib/ngtcp2_err.c',
	'lib/ngtcp2_gaptr.c',
	'lib/ngtcp2_idtr.c',
	'lib/ngtcp2_ksl.c',
	'lib/ngtcp2_log.c',
	'lib/ngtcp2_map.c',
	'lib/ngtcp2_mem.c',
	'lib/ngtcp2_path.c',
	'lib/ngtcp2_pkt.c',
	'lib/ngtcp2_ppe.c',
	'lib/ngtcp2_pq.c',
	'lib/ngtcp2_psl.c',
	'lib/ngtcp2_pv.c',
	'lib/ngtcp2_range.c',
	'lib/ngtcp2_ringbuf.c',
	'lib/ngtcp2_rob.c',
	'lib/ngtcp2_rtb.c',
	'lib/ngtcp2_str.c',
	'lib/ngtcp2_strm.c',
	'lib/ngtcp2_vec.c',
      ]
    }
  ]
}
