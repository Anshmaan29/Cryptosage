# Automated security and functional evaluation

Generated: 2026-11-07T22:02:38.322658+00:00

passed: 234; failed: 0; error: 0; skipped: 0; xfailed: 0. Runner exit: 0. Complete: True.

Recorded runner outcomes apply to the tested revision. Passing tests do not constitute formal protocol verification or production certification.

| Test | Expected behavior | Observed result | Outcome |
| --- | --- | --- | --- |
| tests.test_attack_lab.test_controlled_attack_is_really_rejected[downgrade] | controlled attack is really rejected[downgrade] | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_controlled_attack_is_really_rejected[identity] | controlled attack is really rejected[identity] | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_controlled_attack_is_really_rejected[replay] | controlled attack is really rejected[replay] | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_controlled_attack_is_really_rejected[tamper] | controlled attack is really rejected[tamper] | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_controlled_attack_is_really_rejected[invalid] | controlled attack is really rejected[invalid] | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_unknown_lab_scenario_is_not_success | unknown lab scenario is not success | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_mutation_preserves_original_and_replay_packet | mutation preserves original and replay packet | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_relay_mutations_have_no_crypto_or_client_imports | relay mutations have no crypto or client imports | Test assertions completed without a reported failure. | PASSED |
| tests.test_attack_lab.test_relay_identity_mutation_changes_only_public_identity | relay identity mutation changes only public identity | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_kem_roundtrip_and_malformed_sizes[ML-KEM-768] | kem roundtrip and malformed sizes[ML-KEM-768] | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_kem_roundtrip_and_malformed_sizes[HQC-3] | kem roundtrip and malformed sizes[HQC-3] | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_unsupported_algorithm_fails_closed | unsupported algorithm fails closed | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_enabled_algorithms_have_correct_security_and_names | enabled algorithms have correct security and names | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_signature_authenticates_only_exact_message_and_identity | signature authenticates only exact message and identity | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_hkdf_domain_separation_and_aead_integrity | hkdf domain separation and aead integrity | Test assertions completed without a reported failure. | PASSED |
| tests.test_crypto_primitives.test_attack_cli_emits_parseable_real_json | attack cli emits parseable real json | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_exact_loopback_hosts_are_accepted[127.0.0.1:8001] | exact loopback hosts are accepted[127.0.0.1:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_exact_loopback_hosts_are_accepted[localhost:8001] | exact loopback hosts are accepted[localhost:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[evil.example:8001] | dns rebinding or wrong port host is rejected[evil.example:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[127.0.0.1.evil.example:8001] | dns rebinding or wrong port host is rejected[127.0.0.1.evil.example:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[localhost.evil.example:8001] | dns rebinding or wrong port host is rejected[localhost.evil.example:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[127.0.0.1:8002] | dns rebinding or wrong port host is rejected[127.0.0.1:8002] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[127.0.0.1] | dns rebinding or wrong port host is rejected[127.0.0.1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_dns_rebinding_or_wrong_port_host_is_rejected[0.0.0.0:8001] | dns rebinding or wrong port host is rejected[0.0.0.0:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_untrusted_origin_cannot_read_state_or_change_trust[https://evil.example] | untrusted origin cannot read state or change trust[https://evil.example] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_untrusted_origin_cannot_read_state_or_change_trust[http://localhost:8002] | untrusted origin cannot read state or change trust[http://localhost:8002] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_untrusted_origin_cannot_read_state_or_change_trust[http://127.0.0.1.evil.example:8001] | untrusted origin cannot read state or change trust[http://127.0.0.1.evil.example:8001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_untrusted_origin_cannot_read_state_or_change_trust[null] | untrusted origin cannot read state or change trust[null] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_cross_origin_fetch_metadata_is_rejected_even_with_token[cross-site] | cross origin fetch metadata is rejected even with token[cross-site] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_cross_origin_fetch_metadata_is_rejected_even_with_token[same-site] | cross origin fetch metadata is rejected even with token[same-site] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_same_origin_fetch_can_pin_verified_contact | same origin fetch can pin verified contact | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_csrf_token_is_required_for_mutations[None] | csrf token is required for mutations[None] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_csrf_token_is_required_for_mutations[] | csrf token is required for mutations[] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_csrf_token_is_required_for_mutations[wrong-token] | csrf token is required for mutations[wrong-token] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_json_content_type_required | json content type required | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_message_schema_is_strict_and_size_limited[body0] | message schema is strict and size limited[body0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_message_schema_is_strict_and_size_limited[body1] | message schema is strict and size limited[body1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_message_schema_is_strict_and_size_limited[body2] | message schema is strict and size limited[body2] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_message_schema_is_strict_and_size_limited[body3] | message schema is strict and size limited[body3] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_message_schema_is_strict_and_size_limited[body4] | message schema is strict and size limited[body4] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_total_request_size_is_bounded | total request size is bounded | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_request_size_checks_actual_body_not_only_declared_length | request size checks actual body not only declared length | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_malformed_content_length_is_rejected_safely[not-a-number] | malformed content length is rejected safely[not-a-number] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_malformed_content_length_is_rejected_safely[-1] | malformed content length is rejected safely[-1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_benchmark_schema_rejects_coercion_and_excess_work[10] | benchmark schema rejects coercion and excess work[10] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_benchmark_schema_rejects_coercion_and_excess_work[True] | benchmark schema rejects coercion and excess work[True] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_benchmark_schema_rejects_coercion_and_excess_work[1] | benchmark schema rejects coercion and excess work[1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_benchmark_schema_rejects_coercion_and_excess_work[1001] | benchmark schema rejects coercion and excess work[1001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_static_ui_has_restrictive_csp_and_no_cache | static ui has restrictive csp and no cache | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_state_exposes_public_information_without_key_material | state exposes public information without key material | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_dependency_graph_has_no_private_crypto_operations | relay dependency graph has no private crypto operations | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_rejects_non_loopback_routes[ws://127.0.0.1:8765@evil.example:80] | relay url parser rejects non loopback routes[ws://127.0.0.1:8765@evil.example:80] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_rejects_non_loopback_routes[ws://evil.example:8765] | relay url parser rejects non loopback routes[ws://evil.example:8765] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_rejects_non_loopback_routes[wss://127.0.0.1:8765] | relay url parser rejects non loopback routes[wss://127.0.0.1:8765] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_rejects_non_loopback_routes[ws://127.0.0.1:invalid] | relay url parser rejects non loopback routes[ws://127.0.0.1:invalid] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_rejects_non_loopback_routes[ws://127.0.0.1:8765?redirect=evil] | relay url parser rejects non loopback routes[ws://127.0.0.1:8765?redirect=evil] | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_relay_url_parser_accepts_loopback | relay url parser accepts loopback | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_policy_manager_saves_for_future_sessions_and_requires_confirmation | policy manager saves for future sessions and requires confirmation | Test assertions completed without a reported failure. | PASSED |
| tests.test_local_api.test_reset_cannot_relax_policy_without_confirmation | reset cannot relax policy without confirmation | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_default_prefers_recommended_ml_kem | default prefers recommended ml kem | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_prohibited_algorithm_never_selected_even_if_faster | prohibited algorithm never selected even if faster | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_no_common_algorithms_fails | no common algorithms fails | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_experimental_requires_both_clients_opt_in | experimental requires both clients opt in | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_security_minimum_overrides_performance | security minimum overrides performance | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_invalid_algorithm_offers_rejected[names0] | invalid algorithm offers rejected[names0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_invalid_algorithm_offers_rejected[names1] | invalid algorithm offers rejected[names1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_invalid_algorithm_offers_rejected[names2] | invalid algorithm offers rejected[names2] | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_invalid_algorithm_offers_rejected[ML-KEM-768] | invalid algorithm offers rejected[ML-KEM-768] | Test assertions completed without a reported failure. | PASSED |
| tests.test_policy.test_policy_order_is_symmetric | policy order is symmetric | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_four_flights_and_directional_chat | four flights and directional chat | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_neither_side_usable_before_key_confirmation | neither side usable before key confirmation | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_unknown_contact_rejected_despite_valid_signature | unknown contact rejected despite valid signature | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_unverified_sender_cannot_initiate | unverified sender cannot initiate | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_identity_persistence_and_private_permissions | identity persistence and private permissions | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_fingerprint_verification_and_changed_identity | fingerprint verification and changed identity | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_offer_fields_are_signed[algorithms] | offer fields are signed[algorithms] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_offer_fields_are_signed[policy] | offer fields are signed[policy] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_offer_fields_are_signed[measurements] | offer fields are signed[measurements] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_downgraded_selected_algorithm_fails_signature | downgraded selected algorithm fails signature | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_signed_unacceptable_selection_fails_policy | signed unacceptable selection fails policy | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_valid_signature_from_substituted_identity_rejected | valid signature from substituted identity rejected | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_handshake_offer_and_response_replays_rejected | handshake offer and response replays rejected | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_stale_signed_offer_rejected | stale signed offer rejected | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_signed_modified_kem_key_fails_size_validation | signed modified kem key fails size validation | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_signed_modified_ciphertext_fails_confirmation | signed modified ciphertext fails confirmation | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_initiator_key_confirmation_required | initiator key confirmation required | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_transcript_offer_hash_bound | transcript offer hash bound | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_tamper_does_not_consume_receive_chain | tamper does not consume receive chain | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_replay_and_reordered_message_rejection | replay and reordered message rejection | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_fresh_message_keys_and_nonce_counters | fresh message keys and nonce counters | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_counter_rejected[True] | malformed counter rejected[True] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_counter_rejected[-1] | malformed counter rejected[-1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_counter_rejected[1.0] | malformed counter rejected[1.0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_counter_rejected[0] | malformed counter rejected[0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_counter_rejected[100] | malformed counter rejected[100] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_message_context_authenticated[sid-0000000000000000000000000000000000000000000000000000000000000000] | message context authenticated[sid-0000000000000000000000000000000000000000000000000000000000000000] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_message_context_authenticated[from-Mallory] | message context authenticated[from-Mallory] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_message_context_authenticated[to-Mallory] | message context authenticated[to-Mallory] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_message_context_authenticated[v-bad] | message context authenticated[v-bad] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_rekey_changes_session_and_old_ciphertext_rejected | rekey changes session and old ciphertext rejected | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_ratchet_cap_requires_rekey | ratchet cap requires rekey | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_handshake_timeout_recovery | handshake timeout recovery | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_protocol_rejects_without_session[None] | malformed protocol rejects without session[None] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_protocol_rejects_without_session[packet1] | malformed protocol rejects without session[packet1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_protocol_rejects_without_session[packet2] | malformed protocol rejects without session[packet2] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_protocol_rejects_without_session[packet3] | malformed protocol rejects without session[packet3] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_protocol_rejects_without_session[packet4] | malformed protocol rejects without session[packet4] | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_public_session_does_not_export_secrets | public session does not export secrets | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_response_missing_sid_is_protocol_error | malformed response missing sid is protocol error | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_malformed_peer_name_is_protocol_error | malformed peer name is protocol error | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_hqc_handshake_requires_explicit_policy_agility | hqc handshake requires explicit policy agility | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_contact_trust_pin_persists_on_restart | contact trust pin persists on restart | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_changed_nonce_and_id_are_signed | changed nonce and id are signed | Test assertions completed without a reported failure. | PASSED |
| tests.test_protocol_security.test_duplicate_response_before_ack_is_replay_not_internal_error | duplicate response before ack is replay not internal error | Test assertions completed without a reported failure. | PASSED |
| tests.test_reports.test_absent_report_is_not_a_passing_report | absent report is not a passing report | Test assertions completed without a reported failure. | PASSED |
| tests.test_reports.test_actual_junit_outcomes_remain_distinct | actual junit outcomes remain distinct | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_real_relay_chat_and_fresh_rekey | real relay chat and fresh rekey | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_live_malicious_relay_replay_delivers_once | live malicious relay replay delivers once | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_live_tamper_no_plaintext_then_new_session_recovers | live tamper no plaintext then new session recovers | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_live_downgrade_rejects_handshake | live downgrade rejects handshake | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_network_interruption_discards_session_then_reconnects | network interruption discards session then reconnects | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_periodic_rekey_after_100_messages | periodic rekey after 100 messages | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_recipient_and_session_binding_prevents_wrong_contact_delivery | recipient and session binding prevents wrong contact delivery | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_malformed_relay_registration_closes_cleanly[hello0] | malformed relay registration closes cleanly[hello0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_malformed_relay_registration_closes_cleanly[None] | malformed relay registration closes cleanly[None] | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_malformed_relay_registration_closes_cleanly[Alice] | malformed relay registration closes cleanly[Alice] | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_malformed_relay_registration_closes_cleanly[hello3] | malformed relay registration closes cleanly[hello3] | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_malformed_relay_registration_closes_cleanly[hello4] | malformed relay registration closes cleanly[hello4] | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_delivery_receipt_and_encrypted_history_survive_restart | delivery receipt and encrypted history survive restart | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_delivery_receipt_rejects_forgery_and_wrong_packet | delivery receipt rejects forgery and wrong packet | Test assertions completed without a reported failure. | PASSED |
| tests.test_transport.test_unconfirmed_delivery_timeout_closes_session | unconfirmed delivery timeout closes session | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[downgrade] | v2 catalog exercises real rejection or secure abort[downgrade] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[modified_offers] | v2 catalog exercises real rejection or secure abort[modified offers] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[modified_selected] | v2 catalog exercises real rejection or secure abort[modified selected] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[identity] | v2 catalog exercises real rejection or secure abort[identity] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[invalid_signature] | v2 catalog exercises real rejection or secure abort[invalid signature] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[tamper] | v2 catalog exercises real rejection or secure abort[tamper] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[replay] | v2 catalog exercises real rejection or secure abort[replay] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[handshake_replay] | v2 catalog exercises real rejection or secure abort[handshake replay] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[unsupported] | v2 catalog exercises real rejection or secure abort[unsupported] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[invalid] | v2 catalog exercises real rejection or secure abort[invalid] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[reorder] | v2 catalog exercises real rejection or secure abort[reorder] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_exercises_real_rejection_or_secure_abort[rekey_interruption] | v2 catalog exercises real rejection or secure abort[rekey interruption] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_catalog_is_unique_and_legacy_interface_stays_compatible | v2 catalog is unique and legacy interface stays compatible | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_lab_setup_error_is_not_a_security_success | v2 lab setup error is not a security success | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_lab_unexpected_validation_error_is_inconclusive | v2 lab unexpected validation error is inconclusive | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_lab_acceptance_is_reported_as_failure | v2 lab acceptance is reported as failure | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_lab_exception_during_attack_is_infrastructure_failure | v2 lab exception during attack is infrastructure failure | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_results_do_not_include_packets_or_secret_material | v2 results do not include packets or secret material | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_repeated_runs_create_independent_experiments | v2 repeated runs create independent experiments | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_unsupported_algorithm_tests_actual_whitelist | v2 unsupported algorithm tests actual whitelist | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_attacks.test_v2_unknown_scenario_is_not_a_test_success | v2 unknown scenario is not a test success | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[True] | delay configuration rejects invalid values[True] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[-1] | delay configuration rejects invalid values[-1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[1001] | delay configuration rejects invalid values[1001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[nan] | delay configuration rejects invalid values[nan] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[inf] | delay configuration rejects invalid values[inf] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_delay_configuration_rejects_invalid_values[20] | delay configuration rejects invalid values[20] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[True] | trial count is strict and bounded[True] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[0] | trial count is strict and bounded[0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[1] | trial count is strict and bounded[1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[1001] | trial count is strict and bounded[1001] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[30.0] | trial count is strict and bounded[30.0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_trial_count_is_strict_and_bounded[300] | trial count is strict and bounded[300] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_nearest_rank_percentiles_use_observed_values | nearest rank percentiles use observed values | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_missing_or_invalid_callback_metrics_cannot_claim_measured_handshake | missing or invalid callback metrics cannot claim measured handshake | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_full_callback_has_unrecorded_warmup_and_real_rekey | full callback has unrecorded warmup and real rekey | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_loopback_delay_measurement_and_rekey_are_real | loopback delay measurement and rekey are real | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_benchmarks.test_report_exports_real_rows_charts_and_standalone_html | report exports real rows charts and standalone html | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_history_encrypted_roundtrip_and_allowlist | history encrypted roundtrip and allowlist | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_bounded_history_and_invalid_message_shapes | bounded history and invalid message shapes | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_storage_tampering_never_silently_resets_history | storage tampering never silently resets history | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_wrong_master_key_rejects_existing_history | wrong master key rejects existing history | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_passphrase_storage_requires_original_password | passphrase storage requires original password | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_enabling_password_on_filesystem_store_requires_explicit_migration | enabling password on filesystem store requires explicit migration | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_password_minimum_does_not_create_usable_keystore | password minimum does not create usable keystore | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_v1_identity_migration_preserves_keys_and_pins | v1 identity migration preserves keys and pins | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_invalid_v1_keypair_is_not_migrated | invalid v1 keypair is not migrated | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_identity_secret_and_history_have_distinct_authenticated_purposes | identity secret and history have distinct authenticated purposes | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_malformed_trust_is_rejected[pin0] | malformed trust is rejected[pin0] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_malformed_trust_is_rejected[pin1] | malformed trust is rejected[pin1] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_malformed_trust_is_rejected[pin2] | malformed trust is rejected[pin2] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_malformed_trust_is_rejected[pin3] | malformed trust is rejected[pin3] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_explicit_identity_replacement_requires_both_fingerprints | explicit identity replacement requires both fingerprints | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_safety_number_is_public_stable_and_identity_specific | safety number is public stable and identity specific | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[identity] | symlink storage paths rejected[identity] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[history] | symlink storage paths rejected[history] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[master] | symlink storage paths rejected[master] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[config] | symlink storage paths rejected[config] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[directory] | symlink storage paths rejected[directory] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_symlink_storage_paths_rejected[keystore] | symlink storage paths rejected[keystore] | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_permissive_store_directory_and_key_are_rejected | permissive store directory and key are rejected | Test assertions completed without a reported failure. | PASSED |
| tests.test_v2_storage.test_atomic_write_preserves_existing_file_when_symlink_target_rejected | atomic write preserves existing file when symlink target rejected | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_default_selects_recommended_real_implementation | default selects recommended real implementation | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_prohibition_from_either_endpoint_is_authoritative | prohibition from either endpoint is authoritative | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_minimum_security_cannot_be_reduced_for_performance | minimum security cannot be reduced for performance | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_experimental_requires_both_opt_ins | experimental requires both opt ins | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_symmetric_signed_measurement_selection | symmetric signed measurement selection | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_security_preference_precedes_performance | security preference precedes performance | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_malformed_offers[names0] | reject malformed offers[names0] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_malformed_offers[names1] | reject malformed offers[names1] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_malformed_offers[ML-KEM-768] | reject malformed offers[ML-KEM-768] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_malformed_offers[names3] | reject malformed offers[names3] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_invalid_security_levels[True] | reject invalid security levels[True] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_invalid_security_levels[0] | reject invalid security levels[0] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_invalid_security_levels[6] | reject invalid security levels[6] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_reject_invalid_security_levels[3] | reject invalid security levels[3] | Test assertions completed without a reported failure. | PASSED |
| policy.test_engine.test_nonfinite_and_enormous_measurements_cannot_crash_selection | nonfinite and enormous measurements cannot crash selection | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_decision_reports_actual_eligible_and_restricted_candidates | decision reports actual eligible and restricted candidates | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_rejection_retains_explanation_and_never_relaxes_policy | rejection retains explanation and never relaxes policy | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_missing_peer_capability_is_visible_not_silently_omitted | missing peer capability is visible not silently omitted | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_malformed_policy_rejection_exposes_validation_trace | malformed policy rejection exposes validation trace | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_interval_is_stricter_signed_offer_value_and_trace_symmetric | interval is stricter signed offer value and trace symmetric | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_missing_interval_preserves_v1_100_message_bound | missing interval preserves v1 100 message bound | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[0] | invalid intervals fail securely[0] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[101] | invalid intervals fail securely[101] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[True] | invalid intervals fail securely[True] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[3.5] | invalid intervals fail securely[3.5] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[30] | invalid intervals fail securely[30] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_invalid_intervals_fail_securely[None] | invalid intervals fail securely[None] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_measured_tie_break_is_explained_only_when_gates_tie | measured tie break is explained only when gates tie | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_performance_does_not_claim_to_override_recommended_status | performance does not claim to override recommended status | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_safe_defaults_are_independent_copies_of_safe_baseline | safe defaults are independent copies of safe baseline | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_policy_relaxations_require_explicit_confirmation[change0] | policy relaxations require explicit confirmation[change0] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_policy_relaxations_require_explicit_confirmation[change1] | policy relaxations require explicit confirmation[change1] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_policy_relaxations_require_explicit_confirmation[change2] | policy relaxations require explicit confirmation[change2] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_allowing_previously_prohibited_algorithm_requires_confirmation | allowing previously prohibited algorithm requires confirmation | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_security_floor_cannot_be_bypassed_with_confirmation | security floor cannot be bypassed with confirmation | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_more_restrictive_change_does_not_require_confirmation | more restrictive change does not require confirmation | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_unknown_controls_are_not_silently_ignored[extra0] | unknown controls are not silently ignored[extra0] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_unknown_controls_are_not_silently_ignored[extra1] | unknown controls are not silently ignored[extra1] | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_save_is_atomic_private_and_does_not_mutate_inputs | save is atomic private and does not mutate inputs | Test assertions completed without a reported failure. | PASSED |
| policy.test_v2.test_failed_validation_preserves_existing_policy_file | failed validation preserves existing policy file | Test assertions completed without a reported failure. | PASSED |
| benchmarks.test_runner.test_statistics_use_nearest_rank_p95_and_sample_stdev | statistics use nearest rank p95 and sample stdev | Test assertions completed without a reported failure. | PASSED |
